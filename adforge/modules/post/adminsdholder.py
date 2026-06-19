"""AdminSDHolder persistence check — detect ACL abuse for persistence."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_ADMINSDHOLDER = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"
CVSS40_ADMINSDHOLDER = "CVSS:4.0/AV:N/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
PROTECTED_GROUPS = [
    "Domain Admins", "Enterprise Admins", "Schema Admins",
    "Administrators", "Account Operators", "Backup Operators",
    "Server Operators", "Print Operators", "Replicator",
]


class AdminSdHolder(BaseModule):
    """AdminSDHolder ACL persistence detector."""

    NAME        = "adminsdholder"
    DESCRIPTION = "Check AdminSDHolder for unauthorized ACEs that grant persistence"
    PHASE       = 13
    TAGS        = ["post", "persistence", "adminsdholder", "acl", "mitre-T1484.001"]

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
        )

        if not client.connect():
            return self._make_result(start)

        try:
            await self._check_adminsdholder_acl(client, domain, dc_ip)
            await self._check_protected_users(client, dc_ip)
        finally:
            client.disconnect()

        return self._make_result(start)

    async def _check_adminsdholder_acl(
        self, client: LdapClient, domain: str, dc_ip: str
    ) -> None:
        """Check AdminSDHolder object for non-standard ACEs."""
        dc_parts = ",".join(f"DC={p}" for p in domain.split("."))
        adminsdholder_dn = f"CN=AdminSDHolder,CN=System,{dc_parts}"

        try:
            entries = client.search(
                "(objectClass=container)",
                ["name", "nTSecurityDescriptor", "adminCount"],
                base_dn=adminsdholder_dn,
            )

            # AdminSDHolder ACL analysis requires security descriptor parsing
            # We flag the finding for manual review
            ev = Evidence(
                extra={
                    "adminsdholder_dn": adminsdholder_dn,
                    "entries_found":    len(entries),
                }
            )
            self.new_finding(
                title="AdminSDHolder — Manual ACL Review Required",
                severity=Severity.INFORMATIONAL,
                description=(
                    f"AdminSDHolder object found at {adminsdholder_dn}. "
                    "The AdminSDHolder ACL is propagated to all protected group members every 60 minutes. "
                    "Non-standard ACEs on AdminSDHolder grant attackers persistent privileged access.\n\n"
                    "Manual verification required:\n"
                    "1. Check for unexpected trustees in AdminSDHolder ACL\n"
                    "2. Look for WriteDACL, WriteOwner, GenericAll, GenericWrite permissions\n"
                    "3. Use BloodHound to visualize ACL paths"
                ),
                reproduction_steps=[
                    "PowerView: Get-ObjectAcl -ADSPath 'CN=AdminSDHolder,CN=System,...' -ResolveGUIDs",
                    "BloodHound: Look for AdminSDHolder edges",
                ],
                remediation=(
                    "Remove non-standard ACEs from AdminSDHolder. "
                    "Use tiered administration to limit direct access to Tier-0 objects. "
                    "Monitor SDProp execution (Event 4662) for AdminSDHolder changes."
                ),
                references=["MITRE T1484.001", "adsecurity.org AdminSDHolder"],
                evidence=ev,
                cvss_v31_vector=CVSS_ADMINSDHOLDER,
                cvss_v40_vector=CVSS40_ADMINSDHOLDER,
                target=dc_ip,
            )
        except Exception as exc:
            self.log.debug("AdminSDHolder check failed: %s", exc)

    async def _check_protected_users(self, client: LdapClient, dc_ip: str) -> None:
        """Check for accounts not in Protected Users group that should be."""
        # Get Domain Admins
        da_members = client.search(
            "(&(objectCategory=person)(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,*))",
            ["sAMAccountName", "memberOf"],
        )

        # Get Protected Users group members
        pu_members = client.search(
            "(&(objectCategory=person)(objectClass=user)(memberOf=CN=Protected Users,CN=Users,*))",
            ["sAMAccountName"],
        )
        pu_names = {m.get("sAMAccountName", "") for m in pu_members}

        not_protected = [
            m.get("sAMAccountName", "") for m in da_members
            if m.get("sAMAccountName", "") not in pu_names
        ]

        if not_protected:
            ev = Evidence(
                extra={
                    "da_not_in_protected_users": not_protected,
                    "protected_users_count": len(pu_members),
                }
            )
            self.new_finding(
                title=f"Domain Admins Not in Protected Users Group ({len(not_protected)} accounts)",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(not_protected)} Domain Admin account(s) are not members of the "
                    "'Protected Users' security group: "
                    f"{', '.join(not_protected[:10])}. "
                    "Protected Users disables NTLM auth and Kerberos delegation for privileged accounts."
                ),
                reproduction_steps=["Get-ADGroupMember 'Protected Users'"],
                remediation="Add all privileged accounts to Protected Users group.",
                references=["MITRE T1558", "Protected Users Security Group"],
                evidence=ev,
                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                target=dc_ip,
            )


class TestAdminSdHolder:
    def test_protected_groups(self) -> None:
        assert "Domain Admins" in PROTECTED_GROUPS
        assert "Administrators" in PROTECTED_GROUPS

    def test_cvss_vector(self) -> None:
        assert CVSS_ADMINSDHOLDER.startswith("CVSS:3.1")
