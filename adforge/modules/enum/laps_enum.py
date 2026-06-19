"""LAPS Enumeration — Local Administrator Password Solution coverage."""
from __future__ import annotations
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_NO_LAPS = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS40_NO_LAPS = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_LAPS_READ = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
CVSS40_LAPS_READ = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"

class LapsEnum(BaseModule):
    NAME = "laps_enum"
    DESCRIPTION = "LAPS: coverage, readable passwords, expiration policy"
    PHASE = 2
    TAGS = ["enum", "laps", "ldap", "cwe-522"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        domain = self.config.extra.get("domain", "")
        dc_ip = self.config.extra.get("dc", self.config.target)
        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        client = LdapClient(
            dc_ip=dc_ip, domain=domain,
            username=self.config.extra.get("username", ""),
            password=self.config.extra.get("password", ""),
            nt_hash=self.config.extra.get("hash", ""),
        )
        if not client.connect():
            return self._make_result(start)

        try:
            # Check if LAPS schema exists
            await self.rate_limit()
            laps_check = client.search(
                "(name=ms-Mcs-AdmPwd)",
                ["cn"],
                search_base=f"CN=Schema,CN=Configuration,{client.base_dn}",
            )
            laps_installed = len(laps_check) > 0

            if not laps_installed:
                ev = Evidence(extra={"laps_installed": False})
                self.new_finding(
                    title="LAPS Not Deployed — No Schema Extension",
                    severity=Severity.HIGH,
                    description=(
                        "LAPS (Local Administrator Password Solution) is not installed. "
                        "Without LAPS, local administrator passwords are:\n"
                        "  1. Often identical across all workstations\n"
                        "  2. Never rotated automatically\n"
                        "  3. Trivially exploitable for lateral movement (pass-the-hash)\n\n"
                        "Compromising one workstation's local admin = all workstations."
                    ),
                    reproduction_steps=["Get-ADObject 'CN=ms-Mcs-AdmPwd,CN=Schema,CN=Configuration,...'"],
                    remediation="Deploy Microsoft LAPS or Windows LAPS (built into Win11+/Server 2025).",
                    references=["CWE-522", "MITRE T1078.003"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_NO_LAPS, cvss_v40_vector=CVSS40_NO_LAPS,
                    target=dc_ip,
                )
                return self._make_result(start)

            # Enumerate computers with/without LAPS passwords
            await self.rate_limit()
            computers = client.search(
                "(objectCategory=computer)",
                ["sAMAccountName", "ms-Mcs-AdmPwd", "ms-Mcs-AdmPwdExpirationTime", "operatingSystem"],
            )

            has_laps = []
            no_laps = []
            readable_passwords = []

            for comp in computers:
                name = str(comp.get("sAMAccountName", "?"))
                pwd = comp.get("ms-Mcs-AdmPwd")
                if pwd:
                    has_laps.append(name)
                    readable_passwords.append({"computer": name, "password": str(pwd)[:4] + "***"})
                else:
                    no_laps.append(name)

            coverage = len(has_laps) / len(computers) * 100 if computers else 0

            # Report coverage
            ev = Evidence(
                extra={
                    "total_computers": len(computers),
                    "has_laps": len(has_laps),
                    "no_laps": len(no_laps),
                    "coverage_pct": round(coverage, 1),
                },
            )
            severity = Severity.HIGH if coverage < 50 else Severity.MEDIUM if coverage < 90 else Severity.LOW
            self.new_finding(
                title=f"LAPS Coverage — {coverage:.0f}% ({len(has_laps)}/{len(computers)})",
                severity=severity,
                description=(
                    f"LAPS is installed but covers only {coverage:.0f}% of computers:\n"
                    f"  With LAPS: {len(has_laps)}\n  Without LAPS: {len(no_laps)}\n"
                    + (f"\n  Computers without LAPS: {', '.join(no_laps[:10])}" if no_laps else "")
                ),
                reproduction_steps=[
                    "Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | "
                    "Select Name,@{n='LAPS';e={if($_.'ms-Mcs-AdmPwd'){'Yes'}else{'No'}}}",
                ],
                remediation="Deploy LAPS to all computers. Apply LAPS GPO to all computer OUs.",
                references=["CWE-522"],
                evidence=ev,
                cvss_v31_vector=CVSS_NO_LAPS, cvss_v40_vector=CVSS40_NO_LAPS,
                target=dc_ip,
            )

            # If we can read passwords, that's a finding
            if readable_passwords:
                ev = Evidence(extra={"readable_count": len(readable_passwords)})
                self.new_finding(
                    title=f"LAPS Passwords Readable — {len(readable_passwords)} computers",
                    severity=Severity.HIGH,
                    description=(
                        f"Current user can read LAPS passwords for {len(readable_passwords)} computer(s). "
                        "These are local administrator credentials."
                    ),
                    reproduction_steps=["Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | Where {$_.'ms-Mcs-AdmPwd' -ne $null}"],
                    remediation="Restrict ms-Mcs-AdmPwd read access to designated LAPS admin groups only.",
                    references=["CWE-522", "MITRE T1552"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_LAPS_READ, cvss_v40_vector=CVSS40_LAPS_READ,
                    target=dc_ip,
                )

        finally:
            client.disconnect()
        return self._make_result(start)

class TestLapsEnum:
    def test_phase(self) -> None:
        assert LapsEnum.PHASE == 2
