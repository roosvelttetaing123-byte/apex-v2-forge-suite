"""gMSA Enumeration — Group Managed Service Accounts security audit."""
from __future__ import annotations
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_GMSA_READ = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
CVSS40_GMSA_READ = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_INFO = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
CVSS40_INFO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

GMSA_ATTRS = [
    "sAMAccountName", "msDS-GroupMSAMembership", "msDS-ManagedPasswordInterval",
    "servicePrincipalName", "distinguishedName", "userAccountControl",
    "msDS-ManagedPassword",
]

class GmsaEnum(BaseModule):
    NAME = "gmsa_enum"
    DESCRIPTION = "Enumerate gMSAs, password readers, service principals"
    PHASE = 2
    TAGS = ["enum", "gmsa", "ldap", "cwe-522"]

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
            await self.rate_limit()
            gmsas = client.search(
                "(objectClass=msDS-GroupManagedServiceAccount)", GMSA_ATTRS,
            )
            self.log.info("Found %d gMSA(s)", len(gmsas))

            gmsa_data = []
            readable = []

            for g in gmsas:
                name = str(g.get("sAMAccountName", "?"))
                spns = g.get("servicePrincipalName", [])
                if isinstance(spns, str):
                    spns = [spns]
                interval = int(str(g.get("msDS-ManagedPasswordInterval", 30) or 30))

                # If we can read msDS-ManagedPassword, the current user has read access
                pwd = g.get("msDS-ManagedPassword")
                can_read = pwd is not None and len(str(pwd)) > 0

                info = {"name": name, "spns": spns[:5], "interval_days": interval, "readable": can_read}
                gmsa_data.append(info)
                if can_read:
                    readable.append(info)

            if gmsa_data:
                ev = Evidence(extra={"gmsas": gmsa_data[:20]})
                self.new_finding(
                    title=f"gMSA Inventory — {len(gmsa_data)} managed service accounts",
                    severity=Severity.INFORMATIONAL,
                    description=(
                        f"Group Managed Service Accounts:\n"
                        + "\n".join(
                            f"  {g['name']}: interval={g['interval_days']}d, SPNs={', '.join(g['spns'][:2])}"
                            for g in gmsa_data[:10]
                        )
                    ),
                    reproduction_steps=["Get-ADServiceAccount -Filter * -Properties *"],
                    remediation="Review gMSA password read permissions (PrincipalsAllowedToRetrieveManagedPassword).",
                    references=["CWE-522"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_INFO, cvss_v40_vector=CVSS40_INFO,
                    target=dc_ip,
                )

            if readable:
                ev = Evidence(extra={"readable_gmsas": [r["name"] for r in readable]})
                self.new_finding(
                    title=f"gMSA Password Readable — {len(readable)} accounts",
                    severity=Severity.HIGH,
                    description=(
                        f"Current user can read managed passwords for {len(readable)} gMSA(s): "
                        f"{', '.join(r['name'] for r in readable[:5])}. "
                        "These are 256-character randomly generated passwords that grant service account access."
                    ),
                    reproduction_steps=[
                        "gMSADumper.py -u user -p pass -d domain",
                        "# Or: nxc ldap dc -u user -p pass --gmsa",
                    ],
                    remediation="Restrict PrincipalsAllowedToRetrieveManagedPassword to authorized servers only.",
                    references=["CWE-522", "MITRE T1552"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_GMSA_READ, cvss_v40_vector=CVSS40_GMSA_READ,
                    target=dc_ip,
                )
        finally:
            client.disconnect()
        return self._make_result(start)

class TestGmsaEnum:
    def test_phase(self) -> None:
        assert GmsaEnum.PHASE == 2
