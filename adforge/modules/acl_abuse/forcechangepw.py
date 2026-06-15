"""ForceChangePassword — detect and report ForceChangePassword ACL abuse."""
from __future__ import annotations
import struct, sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
EXTENDED_RIGHT = 0x00000100
# User-Force-Change-Password GUID
FORCE_CHANGE_PWD_GUID = bytes.fromhex("00299570246d11d0a76800aa006e0529")

class ForceChangePw(BaseModule):
    NAME = "forcechangepw"
    DESCRIPTION = "ACL Abuse: ForceChangePassword — reset user passwords without knowing current"
    PHASE = 9
    TAGS = ["acl-abuse", "password", "cwe-284"]

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
            await self.rate_limit()
            # Check high-value targets for ForceChangePassword extended right
            targets = client.search(
                "(&(objectCategory=person)(objectClass=user)(adminCount=1))",
                ["sAMAccountName", "nTSecurityDescriptor"])

            force_change_targets = []
            for user in targets:
                name = str(user.get("sAMAccountName", "?"))
                sd = user.get("nTSecurityDescriptor")
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
                        # ACCESS_ALLOWED_OBJECT_ACE (type 5) with ExtendedRight mask
                        if ace_type == 5:
                            mask = struct.unpack("<I", acl[pos+4:pos+8])[0]
                            if mask & EXTENDED_RIGHT:
                                # Check object type GUID for Force-Change-Password
                                obj_flags = struct.unpack("<I", acl[pos+8:pos+12])[0]
                                if obj_flags & 0x01:
                                    guid_raw = acl[pos+12:pos+28]
                                    if guid_raw == FORCE_CHANGE_PWD_GUID:
                                        force_change_targets.append(name)
                                        break
                        pos += ace_size
                except Exception:
                    pass

            if force_change_targets:
                ev = Evidence(extra={"targets": force_change_targets[:20]})
                self.new_finding(
                    title=f"ForceChangePassword — {len(force_change_targets)} privileged accounts",
                    severity=Severity.HIGH,
                    description=(
                        f"Current user has ForceChangePassword rights on {len(force_change_targets)} "
                        f"privileged account(s): {', '.join(force_change_targets[:10])}\n\n"
                        "This allows resetting passwords WITHOUT knowing the current password — "
                        "direct privilege escalation to any affected account."
                    ),
                    reproduction_steps=[
                        f"net user {force_change_targets[0]} NewP@ssw0rd /domain",
                        f"# Or: Set-ADAccountPassword -Identity {force_change_targets[0]} -NewPassword (ConvertTo-SecureString 'P@ss' -AsPlainText -Force) -Reset",
                        f"# rpcclient: setuserinfo2 {force_change_targets[0]} 23 'NewP@ss'",
                    ],
                    remediation="Remove User-Force-Change-Password extended right from non-admin principals.",
                    references=["CWE-284", "MITRE T1098"],
                    evidence=ev, cvss_v31_vector=CVSS, cvss_v40_vector=CVSS40,
                    mitre_attack=["TA0003/T1098"],
                    target=dc_ip)
        finally:
            client.disconnect()
        return self._make_result(start)

class TestForceChangePw:
    def test_phase(self) -> None: assert ForceChangePw.PHASE == 9
