"""Linked GPO Check — find GPO link manipulation for privilege escalation."""
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

class LinkedGpoCheck(BaseModule):
    NAME = "linked_gpo_check"
    DESCRIPTION = "GPO: detect OUs where current user can modify gPLink (link/unlink GPOs)"
    PHASE = 10
    TAGS = ["gpo-abuse", "privesc", "cwe-284"]

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
            import struct
            WRITE_PROPERTY = 0x00000020
            GENERIC_ALL = 0x10000000
            GENERIC_WRITE = 0x40000000

            await self.rate_limit()
            ous = client.search(
                "(objectCategory=organizationalUnit)",
                ["ou", "distinguishedName", "nTSecurityDescriptor", "gPLink"])

            writable_ous = []
            for ou in ous:
                ou_name = str(ou.get("ou", ou.get("distinguishedName", "?")))
                sd = ou.get("nTSecurityDescriptor")
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
                        if ace_type == 0:
                            mask = struct.unpack("<I", acl[pos+4:pos+8])[0]
                            if mask & (GENERIC_ALL | GENERIC_WRITE | WRITE_PROPERTY):
                                gplink = str(ou.get("gPLink", "") or "")
                                writable_ous.append({
                                    "ou": ou_name,
                                    "dn": str(ou.get("distinguishedName", "")),
                                    "current_gpos": gplink.count("[LDAP://"),
                                })
                                break
                        pos += ace_size
                except Exception:
                    pass

            if writable_ous:
                ev = Evidence(extra={"writable_ous": writable_ous[:20]})
                self.new_finding(
                    title=f"GPO Link Manipulation — {len(writable_ous)} OUs writable",
                    severity=Severity.HIGH,
                    description=(
                        f"Current user can modify gPLink on {len(writable_ous)} OU(s):\n"
                        + "\n".join(f"  {w['ou']} ({w['current_gpos']} GPOs linked)" for w in writable_ous[:10])
                        + "\n\nAn attacker can link a malicious GPO or unlink security GPOs."
                    ),
                    reproduction_steps=[
                        "# Link malicious GPO:",
                        f"Set-GPLink -Guid <malicious-gpo-guid> -Target '{writable_ous[0]['dn']}' -LinkEnabled Yes",
                    ],
                    remediation="Restrict gPLink write access on OUs to Domain Admins only.",
                    references=["CWE-284", "MITRE T1484.001"],
                    evidence=ev, cvss_v31_vector=CVSS, cvss_v40_vector=CVSS40,
                    mitre_attack=["TA0005/T1484.001"],
                    target=dc_ip)
        finally:
            client.disconnect()
        return self._make_result(start)

class TestLinkedGpoCheck:
    def test_phase(self) -> None: assert LinkedGpoCheck.PHASE == 10
