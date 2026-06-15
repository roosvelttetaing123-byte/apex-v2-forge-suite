"""OU Enumeration — Organizational Units, delegation, linked GPOs."""
from __future__ import annotations
import re, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_INFO = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
CVSS40_INFO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

OU_ATTRS = ["ou", "distinguishedName", "gPLink", "description", "whenCreated"]

class OuEnum(BaseModule):
    NAME = "ou_enum"
    DESCRIPTION = "Enumerate OUs, delegation, linked GPOs"
    PHASE = 2
    TAGS = ["enum", "ou", "ldap", "mitre-T1087"]

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
            ous = client.search("(objectCategory=organizationalUnit)", OU_ATTRS)
            self.log.info("Found %d OU(s)", len(ous))

            ou_data = []
            for ou in ous:
                name = str(ou.get("ou", ou.get("distinguishedName", "?")))
                dn = str(ou.get("distinguishedName", ""))
                gplink = str(ou.get("gPLink", "") or "")
                linked_gpos = len(re.findall(r"\[LDAP://", gplink, re.I))
                depth = dn.count(",OU=")
                ou_data.append({"name": name, "dn": dn, "linked_gpos": linked_gpos, "depth": depth})

            if ou_data:
                no_gpo = [o for o in ou_data if o["linked_gpos"] == 0]
                deep = [o for o in ou_data if o["depth"] > 4]
                ev = Evidence(extra={"ous": ou_data[:30], "no_gpo_count": len(no_gpo), "deep_count": len(deep)})
                self.new_finding(
                    title=f"OU Structure — {len(ou_data)} OUs ({len(no_gpo)} without GPOs)",
                    severity=Severity.INFORMATIONAL,
                    description=(
                        f"OU inventory ({len(ou_data)} OUs):\n"
                        + "\n".join(f"  {'  ' * o['depth']}{o['name']} ({o['linked_gpos']} GPOs)" for o in ou_data[:20])
                        + (f"\n\n{len(no_gpo)} OU(s) have no linked GPOs." if no_gpo else "")
                    ),
                    reproduction_steps=["Get-ADOrganizationalUnit -Filter * -Properties gPLink | Select Name,gPLink"],
                    remediation="Review OU structure. Ensure GPOs cover all OUs.",
                    references=["MITRE T1087"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_INFO, cvss_v40_vector=CVSS40_INFO,
                    target=dc_ip,
                )
            self.config.extra["domain_ous"] = ou_data
        finally:
            client.disconnect()
        return self._make_result(start)

class TestOuEnum:
    def test_phase(self) -> None:
        assert OuEnum.PHASE == 2
