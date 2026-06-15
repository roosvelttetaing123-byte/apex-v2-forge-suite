"""AdminCount Enumeration — find orphaned adminCount=1 accounts."""
from __future__ import annotations
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_ORPHAN = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
CVSS40_ORPHAN = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"

PROTECTED_GROUPS = [
    "Domain Admins", "Enterprise Admins", "Administrators",
    "Schema Admins", "Account Operators", "Backup Operators",
    "Server Operators", "Print Operators", "Replicator",
]

class AdminCount(BaseModule):
    NAME = "admin_count"
    DESCRIPTION = "Detect orphaned adminCount=1 accounts not in protected groups"
    PHASE = 2
    TAGS = ["enum", "admin", "ldap", "cwe-284"]

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
            admin_users = client.search(
                "(&(objectCategory=person)(adminCount=1))",
                ["sAMAccountName", "memberOf", "userAccountControl"],
            )

            # Get protected group DNs
            await self.rate_limit()
            pgroups = client.search(
                "(|" + "".join(f"(sAMAccountName={g})" for g in PROTECTED_GROUPS) + ")",
                ["distinguishedName", "sAMAccountName"],
            )
            protected_dns = {str(g.get("distinguishedName", "")) for g in pgroups}

            orphaned = []
            for u in admin_users:
                name = str(u.get("sAMAccountName", "?"))
                member_of = u.get("memberOf", [])
                if isinstance(member_of, str):
                    member_of = [member_of]

                in_protected = any(m in protected_dns for m in member_of)
                if not in_protected:
                    orphaned.append(name)

            if orphaned:
                ev = Evidence(extra={"orphaned": orphaned[:30], "total_admin": len(admin_users)})
                self.new_finding(
                    title=f"Orphaned adminCount — {len(orphaned)} accounts with stale SDProp protection",
                    severity=Severity.MEDIUM,
                    description=(
                        f"{len(orphaned)} account(s) have adminCount=1 but are NOT in any protected group:\n"
                        + "\n".join(f"  {n}" for n in orphaned[:15])
                        + "\n\nThese accounts retain restricted ACLs from SDProp but no longer have "
                        "the group memberships. They may be blind spots for security monitoring."
                    ),
                    reproduction_steps=[
                        "Get-ADUser -Filter {adminCount -eq 1} -Properties memberOf | "
                        "Where {-not ($_.MemberOf | Where {$_ -match 'Admins|Operators'})}",
                    ],
                    remediation="Clear adminCount and reset ACL inheritance on orphaned accounts.",
                    references=["CWE-284"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_ORPHAN, cvss_v40_vector=CVSS40_ORPHAN,
                    target=dc_ip,
                )
        finally:
            client.disconnect()
        return self._make_result(start)

class TestAdminCount:
    def test_groups(self) -> None:
        assert "Domain Admins" in PROTECTED_GROUPS
    def test_phase(self) -> None:
        assert AdminCount.PHASE == 2
