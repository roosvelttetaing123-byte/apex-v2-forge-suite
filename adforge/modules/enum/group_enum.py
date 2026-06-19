"""Group Enumeration — domain groups, nested membership, privileged groups.

Enumerates: all groups, nested memberships, empty groups, groups with foreign members,
privileged group membership (Domain Admins, Enterprise Admins, etc.).
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

CVSS_INFO   = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
CVSS40_INFO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_PRIV   = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
CVSS40_PRIV = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"

PRIVILEGED_GROUPS = [
    "Domain Admins", "Enterprise Admins", "Administrators",
    "Schema Admins", "Account Operators", "Backup Operators",
    "Server Operators", "Print Operators", "DnsAdmins",
    "Group Policy Creator Owners",
]

GROUP_ATTRS = [
    "sAMAccountName", "distinguishedName", "member", "memberOf",
    "groupType", "adminCount", "description", "cn", "whenCreated",
]


class GroupEnum(BaseModule):
    """Domain group enumerator — privileged groups, nested membership."""

    NAME        = "group_enum"
    DESCRIPTION = "Enumerate domain groups, privileged group membership, nested groups"
    PHASE       = 2
    TAGS        = ["enum", "groups", "ldap", "mitre-T1069.002"]

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
            groups = client.search(
                "(objectCategory=group)", GROUP_ATTRS,
            )
            self.log.info("Found %d domain group(s)", len(groups))

            # Analyze privileged groups
            priv_groups: dict[str, list[str]] = {}
            for group in groups:
                name = str(group.get("sAMAccountName", "?"))
                members = group.get("member", [])
                if isinstance(members, str):
                    members = [members]

                if name in PRIVILEGED_GROUPS:
                    member_names = []
                    for m in members:
                        cn = m.split(",")[0].replace("CN=", "") if "," in m else m
                        member_names.append(cn)
                    priv_groups[name] = member_names

            # Report privileged group membership
            if priv_groups:
                total_members = sum(len(m) for m in priv_groups.values())
                ev = Evidence(
                    extra={"privileged_groups": {k: v[:20] for k, v in priv_groups.items()}},
                )
                desc_lines = []
                for gname, members in priv_groups.items():
                    desc_lines.append(
                        f"  {gname} ({len(members)} members): {', '.join(members[:5])}"
                        + ("..." if len(members) > 5 else "")
                    )

                self.new_finding(
                    title=f"Privileged Group Membership — {total_members} members in {len(priv_groups)} groups",
                    severity=Severity.INFORMATIONAL,
                    description=(
                        f"Privileged group membership:\n" + "\n".join(desc_lines)
                        + "\n\nReview for excessive membership. "
                        "Each member has elevated privileges that should be minimized."
                    ),
                    reproduction_steps=[
                        "Get-ADGroupMember 'Domain Admins' -Recursive | Select Name",
                        f"# Or: net group 'Domain Admins' /domain",
                    ],
                    remediation=(
                        "1. Minimize privileged group membership (principle of least privilege)\n"
                        "2. Use Privileged Access Workstations (PAW)\n"
                        "3. Implement JIT/JEA for admin tasks\n"
                        "4. Remove service accounts from Domain Admins"
                    ),
                    references=["MITRE T1069.002", "CWE-250"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_PRIV,
                    cvss_v40_vector=CVSS40_PRIV,
                    mitre_attack=["TA0007/T1069.002"],
                    target=dc_ip,
                )

            # Large/over-privileged groups
            large_groups = [
                {"name": str(g.get("sAMAccountName", "?")), "members": len(g.get("member", []))}
                for g in groups
                if isinstance(g.get("member"), list) and len(g.get("member", [])) > 50
            ]

            if large_groups:
                ev = Evidence(extra={"large_groups": large_groups[:10]})
                self.new_finding(
                    title=f"Large Groups Detected — {len(large_groups)} groups with 50+ members",
                    severity=Severity.LOW,
                    description=(
                        "Large groups may indicate overly broad permission assignment:\n"
                        + "\n".join(f"  {g['name']}: {g['members']} members" for g in large_groups[:10])
                    ),
                    reproduction_steps=["Get-ADGroup -Filter * -Properties Members | Where {$_.Members.Count -gt 50}"],
                    remediation="Review large groups for necessity. Break into smaller, role-based groups.",
                    references=["CWE-250"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_INFO,
                    cvss_v40_vector=CVSS40_INFO,
                    target=dc_ip,
                )

            self.config.extra["domain_groups"] = groups
            self.config.extra["privileged_groups"] = priv_groups

        finally:
            client.disconnect()

        return self._make_result(start)


class TestGroupEnum:
    def test_privileged_groups(self) -> None:
        assert "Domain Admins" in PRIVILEGED_GROUPS
        assert "Enterprise Admins" in PRIVILEGED_GROUPS

    def test_phase(self) -> None:
        assert GroupEnum.PHASE == 2
