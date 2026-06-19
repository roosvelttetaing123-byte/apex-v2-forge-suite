"""Shadow Credentials — msDS-KeyCredentialLink abuse for PKINIT."""
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

class ShadowCreds(BaseModule):
    NAME = "shadow_creds"
    DESCRIPTION = "Shadow Credentials: detect msDS-KeyCredentialLink write access for PKINIT abuse"
    PHASE = 9
    TAGS = ["acl-abuse", "shadow-creds", "pkinit"]

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
            # Check if domain functional level supports PKINIT (2016+)
            schema_version = self.config.extra.get("schema_version", 0)

            await self.rate_limit()
            # Check high-value targets for GenericAll/GenericWrite (which allows writing msDS-KeyCredentialLink)
            targets = client.search(
                "(|(adminCount=1)(objectCategory=computer))",
                ["sAMAccountName", "msDS-KeyCredentialLink", "nTSecurityDescriptor", "objectCategory"])

            writable = []
            existing_kcl = []

            for obj in targets[:200]:
                name = str(obj.get("sAMAccountName", "?"))
                kcl = obj.get("msDS-KeyCredentialLink")

                if kcl:
                    existing_kcl.append(name)

                sd = obj.get("nTSecurityDescriptor")
                if not sd or not isinstance(sd, bytes) or len(sd) < 20:
                    continue

                # Check for GenericAll/GenericWrite which allows writing msDS-KeyCredentialLink
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
                            if mask & (0x10000000 | 0x40000000):  # GenericAll | GenericWrite
                                writable.append(name)
                                break
                        pos += ace_size
                except Exception:
                    pass

            if writable:
                ev = Evidence(extra={"writable": writable[:20]})
                self.new_finding(
                    title=f"Shadow Credentials — {len(writable)} objects writable for KCL injection",
                    severity=Severity.HIGH,
                    description=(
                        f"GenericAll/GenericWrite on {len(writable)} object(s) allows Shadow Credentials attack:\n"
                        + "\n".join(f"  {w}" for w in writable[:10])
                        + "\n\nAttack: Write a KeyCredentialLink → authenticate via PKINIT → "
                        "obtain TGT → extract NT hash (UnPAC-the-hash)."
                    ),
                    reproduction_steps=[
                        f"# Add shadow credential:",
                        f"certipy shadow auto -u user@{domain} -p pass -target {writable[0]} -dc-ip {dc_ip}",
                        f"# Or: whisker.exe add /target:{writable[0]} /domain:{domain} /dc:{dc_ip}",
                        f"# Get TGT and NT hash via PKINIT:",
                        f"certipy auth -pfx <output>.pfx -domain {domain} -dc-ip {dc_ip}",
                    ],
                    remediation=(
                        "1. Remove GenericAll/GenericWrite from non-admin principals\n"
                        "2. Monitor msDS-KeyCredentialLink modifications (Event ID 5136)\n"
                        "3. Restrict PKINIT to authorized principals"
                    ),
                    references=["CWE-284", "MITRE T1556"],
                    evidence=ev, cvss_v31_vector=CVSS, cvss_v40_vector=CVSS40,
                    mitre_attack=["TA0006/T1556"],
                    target=dc_ip)

            if existing_kcl:
                ev = Evidence(extra={"accounts_with_kcl": existing_kcl[:20]})
                self.new_finding(
                    title=f"Existing KeyCredentialLinks — {len(existing_kcl)} objects (audit)",
                    severity=Severity.INFORMATIONAL,
                    description=(
                        f"{len(existing_kcl)} objects already have msDS-KeyCredentialLink set: "
                        f"{', '.join(existing_kcl[:10])}. Review for unauthorized shadow credentials."
                    ),
                    reproduction_steps=["Get-ADObject -Filter {msDS-KeyCredentialLink -like '*'} -Properties msDS-KeyCredentialLink"],
                    remediation="Audit existing KeyCredentialLinks for unauthorized entries.",
                    references=["MITRE T1556"],
                    evidence=ev,
                    cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
                    cvss_v40_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
                    target=dc_ip)
        finally:
            client.disconnect()
        return self._make_result(start)

class TestShadowCreds:
    def test_phase(self) -> None: assert ShadowCreds.PHASE == 9
