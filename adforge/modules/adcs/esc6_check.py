"""ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA (allows SAN specification)."""
from __future__ import annotations
import asyncio, shutil, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"

class Esc6Check(BaseModule):
    NAME = "esc6_check"
    DESCRIPTION = "ESC6: CA has EDITF_ATTRIBUTESUBJECTALTNAME2 — arbitrary SAN in any cert"
    PHASE = 11
    TAGS = ["adcs", "esc6"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        dc_ip = self.config.extra.get("dc", self.config.target)
        domain = self.config.extra.get("domain", "")
        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # Check via certutil or RPC
        cas = self.config.extra.get("adcs_cas", [])
        for ca_info in cas:
            ca_name = ca_info.get("name", "?")
            ca_host = ca_info.get("host", dc_ip)

            await self.rate_limit()
            certutil = shutil.which("certutil")
            if certutil:
                try:
                    proc = await asyncio.create_subprocess_exec(
                        certutil, "-config", f"{ca_host}\\{ca_name}", "-getreg", "policy\\EditFlags",
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=15)
                    output = stdout.decode(errors="ignore")

                    # EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000 (bit 18)
                    if "EDITF_ATTRIBUTESUBJECTALTNAME2" in output or "40000" in output:
                        ev = Evidence(response_raw=output[:500], extra={"ca": ca_name, "host": ca_host})
                        self.new_finding(
                            title=f"ESC6 — {ca_name}: EDITF_ATTRIBUTESUBJECTALTNAME2 enabled",
                            severity=Severity.CRITICAL,
                            description=(
                                f"CA {ca_name} on {ca_host} has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled. "
                                "This allows ANY enrollee to specify an arbitrary Subject Alternative Name (SAN) "
                                "in ANY certificate request, regardless of template configuration.\n\n"
                                "An attacker can request a certificate with SAN=administrator@domain "
                                "and authenticate as Domain Admin."
                            ),
                            reproduction_steps=[
                                f"certipy req -u user@{domain} -p pass -target {ca_host} "
                                f"-ca '{ca_name}' -template User -upn administrator@{domain}",
                                f"certipy auth -pfx administrator.pfx -domain {domain}",
                            ],
                            remediation=(
                                f"certutil -config \"{ca_host}\\{ca_name}\" -setreg "
                                "policy\\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2\n"
                                "net stop certsvc && net start certsvc"
                            ),
                            references=["CWE-295", "SpecterOps ESC6"],
                            evidence=ev, cvss_v31_vector=CVSS, cvss_v40_vector=CVSS40, target=dc_ip)
                except Exception:
                    pass

        return self._make_result(start)

class TestEsc6Check:
    def test_phase(self) -> None: assert Esc6Check.PHASE == 11
