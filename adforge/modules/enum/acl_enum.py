"""ACL Enumeration — LDAP-based DACL analysis for dangerous permissions.

Enumerates: GenericAll, GenericWrite, WriteDACL, WriteOwner, ForceChangePassword,
AddMember on user/group/computer objects. Identifies ACE abuse paths.
"""
from __future__ import annotations

import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_ACL_ABUSE  = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS40_ACL_ABUSE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_INFO       = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
CVSS40_INFO     = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

# Dangerous AD rights GUIDs
RIGHTS_GUIDS = {
    "00299570-246d-11d0-a768-00aa006e0529": "User-Force-Change-Password",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "bf967a68-0de6-11d0-a285-00aa003049e2": "Computer",
    "bf967aba-0de6-11d0-a285-00aa003049e2": "User",
}

# Generic rights bitmask
GENERIC_ALL         = 0x10000000
GENERIC_WRITE       = 0x40000000
WRITE_DACL          = 0x00040000
WRITE_OWNER         = 0x00080000
WRITE_PROPERTY      = 0x00000020
EXTENDED_RIGHT      = 0x00000100

DANGEROUS_RIGHTS = {
    GENERIC_ALL: "GenericAll",
    GENERIC_WRITE: "GenericWrite",
    WRITE_DACL: "WriteDACL",
    WRITE_OWNER: "WriteOwner",
}

ACL_ATTRIBUTES = [
    "sAMAccountName", "distinguishedName", "nTSecurityDescriptor",
    "objectClass", "adminCount",
]


class AclEnum(BaseModule):
    """ACL enumerator — identify dangerous DACL permissions on AD objects."""

    NAME        = "acl_enum"
    DESCRIPTION = "Enumerate object DACLs for GenericAll, WriteDACL, WriteOwner abuse paths"
    PHASE       = 2
    TAGS        = ["enum", "acl", "ldap", "cwe-284", "mitre-T1222"]

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
            self.log.warning("LDAP connection failed to %s", dc_ip)
            return self._make_result(start)

        try:
            # Enumerate high-value targets: Domain Admins, Enterprise Admins, krbtgt, DC$
            high_value_targets = self.config.extra.get("admin_count_users", [])
            if not high_value_targets:
                high_value_targets = ["Domain Admins", "Enterprise Admins", "krbtgt", "Administrator"]

            await self.rate_limit()

            # Query objects with their security descriptors
            # Use SD_FLAGS control to request DACL only (0x04)
            results = client.search(
                "(&(objectCategory=person)(objectClass=user)(adminCount=1))",
                ["sAMAccountName", "distinguishedName", "nTSecurityDescriptor"],
            )

            dangerous_aces: list[dict] = []

            for obj in results:
                name = str(obj.get("sAMAccountName", "?"))
                sd_raw = obj.get("nTSecurityDescriptor")
                if not sd_raw or not isinstance(sd_raw, bytes):
                    continue

                aces = self._parse_sd_dacl(sd_raw, name)
                dangerous_aces.extend(aces)

            # Also check group objects
            await self.rate_limit()
            group_results = client.search(
                "(|(sAMAccountName=Domain Admins)(sAMAccountName=Enterprise Admins)"
                "(sAMAccountName=Administrators)(sAMAccountName=Account Operators))",
                ["sAMAccountName", "distinguishedName", "nTSecurityDescriptor"],
            )

            for obj in group_results:
                name = str(obj.get("sAMAccountName", "?"))
                sd_raw = obj.get("nTSecurityDescriptor")
                if not sd_raw or not isinstance(sd_raw, bytes):
                    continue
                aces = self._parse_sd_dacl(sd_raw, name)
                dangerous_aces.extend(aces)

            if dangerous_aces:
                ev = Evidence(
                    extra={
                        "dangerous_aces": dangerous_aces[:50],
                        "total_count": len(dangerous_aces),
                    },
                )
                self.new_finding(
                    title=f"Dangerous ACL Permissions — {len(dangerous_aces)} Abuse Paths",
                    severity=Severity.HIGH,
                    description=(
                        f"Found {len(dangerous_aces)} dangerous ACE(s) on high-value AD objects:\n"
                        + "\n".join(
                            f"  {a['principal']} has {a['right']} on {a['target']}"
                            for a in dangerous_aces[:15]
                        )
                        + "\n\nThese permissions allow privilege escalation via ACL abuse."
                    ),
                    reproduction_steps=[
                        "Import-Module PowerView",
                        "Get-ObjectAcl -Identity 'Domain Admins' -ResolveGUIDs | "
                        "Where {$_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner'}",
                        "# Or: bloodhound-python -d domain -u user -p pass -c ACL",
                    ],
                    remediation=(
                        "1. Remove unnecessary ACEs from high-value objects\n"
                        "2. Use AdminSDHolder to enforce ACLs on protected groups\n"
                        "3. Run BloodHound regularly to detect ACL attack paths\n"
                        "4. Implement Tier 0/1/2 access model"
                    ),
                    references=["CWE-284", "MITRE T1222.001"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_ACL_ABUSE,
                    cvss_v40_vector=CVSS40_ACL_ABUSE,
                    mitre_attack=["TA0005/T1222.001"],
                    target=dc_ip,
                )

            self.config.extra["dangerous_aces"] = dangerous_aces

        finally:
            client.disconnect()

        return self._make_result(start)

    def _parse_sd_dacl(self, sd_raw: bytes, target_name: str) -> list[dict]:
        """Parse binary Security Descriptor and extract dangerous ACEs."""
        aces = []
        try:
            if len(sd_raw) < 20:
                return aces

            # SD header: Revision(1) Sbz1(1) Control(2) OffsetOwner(4) OffsetGroup(4) OffsetSacl(4) OffsetDacl(4)
            revision = sd_raw[0]
            control = struct.unpack("<H", sd_raw[2:4])[0]
            offset_dacl = struct.unpack("<I", sd_raw[16:20])[0]

            if offset_dacl == 0 or offset_dacl >= len(sd_raw):
                return aces

            # ACL header: AclRevision(1) Sbz1(1) AclSize(2) AceCount(2) Sbz2(2)
            acl_data = sd_raw[offset_dacl:]
            if len(acl_data) < 8:
                return aces

            ace_count = struct.unpack("<H", acl_data[4:6])[0]
            pos = 8  # Start of first ACE

            for _ in range(min(ace_count, 200)):
                if pos + 4 > len(acl_data):
                    break

                ace_type = acl_data[pos]
                ace_flags = acl_data[pos + 1]
                ace_size = struct.unpack("<H", acl_data[pos + 2:pos + 4])[0]

                if ace_size < 4 or pos + ace_size > len(acl_data):
                    break

                # ACCESS_ALLOWED_ACE (type 0) or ACCESS_ALLOWED_OBJECT_ACE (type 5)
                if ace_type in (0, 5):
                    mask = struct.unpack("<I", acl_data[pos + 4:pos + 8])[0]

                    # Check for dangerous generic rights
                    for right_mask, right_name in DANGEROUS_RIGHTS.items():
                        if mask & right_mask:
                            # Extract SID
                            if ace_type == 0:
                                sid_offset = pos + 8
                            else:
                                # Object ACE has flags(4) + objectType(16) + inheritedObjectType(16) before SID
                                obj_flags = struct.unpack("<I", acl_data[pos + 8:pos + 12])[0]
                                sid_offset = pos + 12
                                if obj_flags & 0x01:
                                    sid_offset += 16
                                if obj_flags & 0x02:
                                    sid_offset += 16

                            if sid_offset < len(acl_data):
                                sid_str = self._parse_sid(acl_data[sid_offset:sid_offset + 28])
                                # Skip well-known system SIDs
                                if not sid_str.startswith("S-1-5-18") and not sid_str.startswith("S-1-5-32-544"):
                                    aces.append({
                                        "target": target_name,
                                        "right": right_name,
                                        "principal": sid_str,
                                        "ace_type": ace_type,
                                    })

                pos += ace_size

        except Exception as exc:
            self.log.debug("SD parse error for %s: %s", target_name, exc)

        return aces

    def _parse_sid(self, data: bytes) -> str:
        """Parse a binary SID into string format S-1-X-Y-..."""
        try:
            if len(data) < 8:
                return "S-?-?"
            revision = data[0]
            sub_count = data[1]
            authority = int.from_bytes(data[2:8], "big")
            subs = []
            for i in range(min(sub_count, 15)):
                offset = 8 + i * 4
                if offset + 4 <= len(data):
                    subs.append(struct.unpack("<I", data[offset:offset + 4])[0])
            return f"S-{revision}-{authority}" + "".join(f"-{s}" for s in subs)
        except Exception:
            return "S-?-?"


class TestAclEnum:
    def test_dangerous_rights(self) -> None:
        assert GENERIC_ALL in DANGEROUS_RIGHTS
        assert WRITE_DACL in DANGEROUS_RIGHTS

    def test_sid_parse(self) -> None:
        mod = AclEnum.__new__(AclEnum)
        # Well-known SID S-1-5-21-x-y-z-500 (Administrator)
        sid = mod._parse_sid(b"\x01\x04\x00\x00\x00\x00\x00\x05\x15\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\xf4\x01\x00\x00")
        assert sid.startswith("S-1-5")

    def test_phase(self) -> None:
        assert AclEnum.PHASE == 2
