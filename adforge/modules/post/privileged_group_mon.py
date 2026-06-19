"""Privileged Group Monitoring — detect unauthorized changes to privileged groups."""
from __future__ import annotations
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"

MONITORED_GROUPS = [
    "Domain Admins", "Enterprise Admins", "Administrators",
    "Schema Admins", "Account Operators", "Backup Operators",
    "Server Operators", "DnsAdmins", "Group Policy Creator Owners",
]

class PrivilegedGroupMon(BaseModule):
    NAME = "privileged_group_mon"
    DESCRIPTION = "Monitor privileged groups for excessive/unauthorized membership"
    PHASE = 13
    TAGS = ["post", "monitoring", "cwe-250"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        dc_ip = self.config.extra.get("dc", self.config.target)
        domain = self.config.extra.get("domain", "")
        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        client = LdapClient(dc_ip=dc_ip, domain=domain,
            username=self.config.extra.get("username", ""),
            password=self.config.extra.get("password", ""),
            nt_hash=self.config.extra.get("hash", ""))
        if not client.connect(): return self._make_result(start)

        try:
            group_status = {}
            total_priv_users = 0

            for group_name in MONITORED_GROUPS:
                await self.rate_limit()
                results = client.search(
                    f"(sAMAccountName={group_name})",
                    ["sAMAccountName", "member", "whenChanged"])

                if not results:
                    continue

                members = results[0].get("member", [])
                if isinstance(members, str):
                    members = [members]

                member_names = []
                for m in members:
                    cn = m.split(",")[0].replace("CN=", "") if "," in m else m
                    member_names.append(cn)

                group_status[group_name] = {
                    "members": member_names,
                    "count": len(member_names),
                }
                total_priv_users += len(member_names)

            # Identify excessive memberships (service accounts in DA, etc.)
            excessive = {
                g: info for g, info in group_status.items()
                if info["count"] > 5 and g in ("Domain Admins", "Enterprise Admins")
            }

            if group_status:
                ev = Evidence(extra={
                    "groups": {g: i["count"] for g, i in group_status.items()},
                    "total_privileged": total_priv_users,
                    "details": {g: i["members"][:10] for g, i in group_status.items()},
                })

                severity = Severity.MEDIUM if excessive else Severity.INFORMATIONAL
                self.new_finding(
                    title=f"Privileged Group Audit — {total_priv_users} members across {len(group_status)} groups",
                    severity=severity,
                    description=(
                        f"Privileged group membership snapshot:\n"
                        + "\n".join(
                            f"  {g}: {i['count']} members" + (" [EXCESSIVE]" if g in excessive else "")
                            + f" — {', '.join(i['members'][:5])}" + ("..." if i['count'] > 5 else "")
                            for g, i in group_status.items()
                        )
                        + (f"\n\n{len(excessive)} group(s) have excessive membership (>5)." if excessive else "")
                    ),
                    reproduction_steps=[
                        "Get-ADGroup -Filter {adminCount -eq 1} | ForEach { Get-ADGroupMember $_ | Measure } | Select Name,Count",
                    ],
                    remediation=(
                        "1. Minimize Domain Admins to <5 members\n"
                        "2. Remove service accounts from privileged groups (use delegation)\n"
                        "3. Implement JIT/JEA for admin tasks\n"
                        "4. Set up alerts for group membership changes (Event ID 4728/4732)"
                    ),
                    references=["CWE-250", "MITRE T1078.002"],
                    evidence=ev, cvss_v31_vector=CVSS, cvss_v40_vector=CVSS40,
                    target=dc_ip)
        finally:
            client.disconnect()
        return self._make_result(start)

class TestPrivilegedGroupMon:
    def test_groups(self) -> None: assert "Domain Admins" in MONITORED_GROUPS
    def test_phase(self) -> None: assert PrivilegedGroupMon.PHASE == 13
