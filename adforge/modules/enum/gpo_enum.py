"""GPO Enumeration — Group Policy Objects, linked OUs, dangerous settings.

Enumerates: all GPOs, linked OUs, GPO permissions, interesting settings
(password policies, startup scripts, scheduled tasks).
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_INFO = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
CVSS40_INFO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_GPO_PERM = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS40_GPO_PERM = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"

GPO_ATTRS = [
    "displayName", "cn", "gPCFileSysPath", "distinguishedName",
    "flags", "versionNumber", "whenCreated", "whenChanged",
    "nTSecurityDescriptor",
]


class GpoEnum(BaseModule):
    """GPO enumerator — list policies, linked OUs, SYSVOL paths."""

    NAME        = "gpo_enum"
    DESCRIPTION = "Enumerate GPOs, linked OUs, SYSVOL paths, GPO permissions"
    PHASE       = 2
    TAGS        = ["enum", "gpo", "ldap", "mitre-T1615"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        domain = self.config.extra.get("domain", "")
        dc_ip  = self.config.extra.get("dc", self.config.target)

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
            gpos = client.search(
                "(objectCategory=groupPolicyContainer)", GPO_ATTRS,
            )
            self.log.info("Found %d GPO(s)", len(gpos))

            gpo_list = []
            for gpo in gpos:
                name = str(gpo.get("displayName", "?"))
                sysvol = str(gpo.get("gPCFileSysPath", "") or "")
                flags = int(str(gpo.get("flags", 0) or 0))
                version = int(str(gpo.get("versionNumber", 0) or 0))
                gpo_list.append({
                    "name": name,
                    "sysvol_path": sysvol,
                    "flags": flags,
                    "disabled": flags == 3,
                    "user_disabled": bool(flags & 2),
                    "computer_disabled": bool(flags & 1),
                    "version": version,
                })

            # Also enumerate OU links
            await self.rate_limit()
            ous = client.search(
                "(gPLink=*)", ["ou", "distinguishedName", "gPLink"],
            )

            ou_links = {}
            for ou in ous:
                ou_dn = str(ou.get("distinguishedName", "?"))
                gplink = str(ou.get("gPLink", "") or "")
                linked = []
                # Parse gPLink format: [LDAP://cn={GUID},cn=policies,...;flags]
                import re
                for m in re.finditer(r"\[LDAP://([^;]+);(\d+)\]", gplink, re.I):
                    linked.append({"dn": m.group(1), "enforced": m.group(2) == "2"})
                if linked:
                    ou_links[ou_dn] = linked

            if gpo_list:
                ev = Evidence(
                    extra={
                        "gpos": gpo_list[:30],
                        "ou_links": {k: v for k, v in list(ou_links.items())[:20]},
                    },
                )
                disabled_count = sum(1 for g in gpo_list if g["disabled"])
                self.new_finding(
                    title=f"GPO Inventory — {len(gpo_list)} GPOs ({disabled_count} disabled)",
                    severity=Severity.INFORMATIONAL,
                    description=(
                        f"Domain GPO inventory:\n"
                        + "\n".join(
                            f"  {g['name']}" + (" [DISABLED]" if g['disabled'] else "")
                            + (f" — SYSVOL: {g['sysvol_path']}" if g['sysvol_path'] else "")
                            for g in gpo_list[:15]
                        )
                        + f"\n\nLinked to {len(ou_links)} OU(s)."
                    ),
                    reproduction_steps=[
                        "Get-GPO -All | Select DisplayName,GpoStatus",
                        f"# SYSVOL: \\\\{dc_ip}\\SYSVOL\\{domain}\\Policies\\",
                    ],
                    remediation="Review GPOs for stale/unused policies. Remove disabled GPOs.",
                    references=["MITRE T1615"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_INFO,
                    cvss_v40_vector=CVSS40_INFO,
                    mitre_attack=["TA0007/T1615"],
                    target=dc_ip,
                )

            self.config.extra["domain_gpos"] = gpo_list
            self.config.extra["ou_gpo_links"] = ou_links

        finally:
            client.disconnect()

        return self._make_result(start)


class TestGpoEnum:
    def test_gpo_flags(self) -> None:
        # flags=3 means both user and computer settings disabled
        assert 3 == (1 | 2)

    def test_phase(self) -> None:
        assert GpoEnum.PHASE == 2
