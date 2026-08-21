"""ACL scanner — enumerate dangerous ACEs on high-value AD objects.

Checks nTSecurityDescriptor on:
  - The domain root object (GenericAll → domain takeover)
  - Domain Controllers OU and DC machine accounts
  - AdminSDHolder (all protected accounts inherit this)
  - Privileged group objects (Domain Admins, etc.)
  - krbtgt account

Dangerous rights checked:
  GenericAll, GenericWrite, WriteDACL, WriteOwner, AllExtendedRights,
  WriteProperty (ForceChangePassword GUID, SelfMembership GUID)
"""
from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_ACL      = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS40_ACL    = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_ACL_HIGH = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
CVSS40_ACL_HIGH = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
# Active Directory well-known extended right GUIDs
GUID_REPLICATION_GET_CHANGES     = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GUID_REPLICATION_GET_CHANGES_ALL = "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2"
GUID_FORCE_CHANGE_PASSWORD       = "00299570-246d-11d0-a768-00aa006e0529"
GUID_SELF_MEMBERSHIP             = "bf9679c0-0de6-11d0-a285-00aa003049e2"
GUID_WRITE_MEMBERS               = "bf9679c0-0de6-11d0-a285-00aa003049e2"

# Well-known SIDs to skip (legitimate admin SIDs)
SKIP_SIDS = frozenset({
    "S-1-5-18",          # SYSTEM
    "S-1-5-32-544",      # Administrators (builtin)
    "S-1-3-0",           # Creator Owner
    "S-1-5-9",           # Enterprise Domain Controllers
    "S-1-5-10",          # Principal Self
    # Domain Admins SIDs vary by domain (S-1-5-21-...-512) — checked dynamically
})

DANGEROUS_RIGHTS = {
    "GenericAll":         "Full control over object — modify any attribute, reset password",
    "GenericWrite":       "Write to most attributes — can modify delegation, SPNs, group members",
    "WriteDACL":          "Modify discretionary ACL — can grant self GenericAll",
    "WriteOwner":         "Change object owner — new owner can modify ACL (grant self GenericAll)",
    "AllExtendedRights":  "All extended rights including DCSync replication, ForceChangePassword",
    "WriteProperty":      "Write specific property — may allow SPN/delegation modification",
    "Self":               "Self-modification rights (e.g., add self to group)",
}


class AclScanner(BaseModule):
    """AD ACL abuse path scanner — enumerate dangerous ACEs on high-value objects."""

    NAME        = "acl_scanner"
    DESCRIPTION = "Find dangerous ACEs on AD objects (domain root, DCs, AdminSDHolder, privileged groups)"
    PHASE       = 9
    TAGS        = ["acl-abuse", "dacl", "privilege-escalation", "mitre-T1484.001"]

    async def run(self) -> ModuleResult:
        start  = time.monotonic()
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
            return self._make_result(start)

        try:
            dc_parts = ",".join(f"DC={p}" for p in domain.split("."))

            # Check ACLs on high-value objects
            await self.rate_limit()
            await self._check_object_acl(
                client, dc_ip, dc_parts,
                "(objectClass=domain)", "Domain Root Object",
                Severity.CRITICAL,
            )

            await self.rate_limit()
            await self._check_object_acl(
                client, dc_ip, f"CN=AdminSDHolder,CN=System,{dc_parts}",
                "(objectClass=*)", "AdminSDHolder",
                Severity.CRITICAL,
                search_scope="BASE",
            )

            await self.rate_limit()
            await self._check_object_acl(
                client, dc_ip, f"CN=krbtgt,CN=Users,{dc_parts}",
                "(sAMAccountName=krbtgt)", "krbtgt Account",
                Severity.CRITICAL,
                search_scope="BASE",
            )

            # Privileged groups
            for group in ["Domain Admins", "Enterprise Admins", "Schema Admins"]:
                await self.rate_limit()
                await self._check_object_acl(
                    client, dc_ip, f"CN={group},CN=Users,{dc_parts}",
                    f"(cn={group})", f"Privileged Group: {group}",
                    Severity.HIGH,
                    search_scope="BASE",
                )

            # Domain Controllers OU
            await self.rate_limit()
            await self._check_object_acl(
                client, dc_ip, f"OU=Domain Controllers,{dc_parts}",
                "(objectClass=organizationalUnit)", "Domain Controllers OU",
                Severity.HIGH,
                search_scope="BASE",
            )

        finally:
            client.disconnect()

        return self._make_result(start)

    async def _check_object_acl(
        self,
        client: LdapClient,
        dc_ip: str,
        base_dn: str,
        search_filter: str,
        object_label: str,
        finding_severity: Severity,
        search_scope: str = "BASE",
    ) -> None:
        """Retrieve nTSecurityDescriptor for an object and analyze it."""
        from ldap3 import SECURITY_DESCRIPTOR_CONTROL

        entries = client.search(
            search_filter,
            ["distinguishedName", "nTSecurityDescriptor", "sAMAccountName", "cn"],
            base_dn=base_dn,
            search_scope=search_scope,
            controls=[SECURITY_DESCRIPTOR_CONTROL],
        )

        for entry in entries:
            dn = entry.get("dn", base_dn)
            sd = entry.get("nTSecurityDescriptor_raw") or entry.get("nTSecurityDescriptor", "")
            if not sd:
                continue

            issues = self._analyze_security_descriptor(sd, dn)
            if not issues:
                continue

            for issue in issues:
                ev = Evidence(extra={
                    "object_label": object_label,
                    "object_dn":    dn,
                    "trustee_sid":  issue["trustee"],
                    "right":        issue["right"],
                    "description":  DANGEROUS_RIGHTS.get(issue["right"], "Elevated access"),
                })
                self.new_finding(
                    title=f"Dangerous ACE on {object_label} — {issue['right']} granted to {issue['trustee']}",
                    severity=finding_severity,
                    description=(
                        f"Dangerous ACE detected on {object_label} ({dn}):\n\n"
                        f"  Trustee SID: {issue['trustee']}\n"
                        f"  Right:       {issue['right']}\n"
                        f"  Impact:      {DANGEROUS_RIGHTS.get(issue['right'], 'Elevated access')}\n\n"
                        f"Non-default principal '{issue['trustee']}' has {issue['right']} "
                        f"on a high-value AD object. This enables direct privilege escalation:\n"
                        "  • GenericAll/GenericWrite → modify any attribute, Kerberoast service accounts\n"
                        "  • WriteDACL/WriteOwner → grant self GenericAll → full object control\n"
                        "  • AllExtendedRights on domain root → DCSync replication rights"
                    ),
                    reproduction_steps=[
                        "# BloodHound: automatic detection of all ACL paths",
                        f"Get-ObjectAcl -Identity '{object_label}' -ResolveGUIDs | "
                        "Where {$_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner'}",
                        f"# Abuse example (WriteDACL → GenericAll → ForceChangePassword):",
                        f"Add-DomainObjectAcl -TargetIdentity '{object_label}' -PrincipalIdentity attacker "
                        "-Rights All",
                    ],
                    remediation=(
                        f"Remove the unexpected ACE for SID {issue['trustee']} from {object_label}. "
                        "Use BloodHound to identify all ACL-based attack paths. "
                        "Regularly audit ACLs on high-value objects with PowerView or ADACLScanner."
                    ),
                    references=[
                        "MITRE TA0004/T1484.001",
                        "https://attack.mitre.org/techniques/T1484/001/",
                        "https://github.com/BloodHoundAD/BloodHound",
                    ],
                    evidence=ev,
                    cvss_v31_vector=CVSS_ACL_HIGH if finding_severity == Severity.CRITICAL else CVSS_ACL,
                    cvss_v40_vector=CVSS40_ACL_HIGH,
                    mitre_attack=["TA0004/T1484.001"],
                    target=dc_ip,
                )

    def _analyze_security_descriptor(self, raw_sd: object, dn: str) -> list[dict]:
        """Parse binary security descriptor and return list of dangerous ACE issues."""
        issues: list[dict] = []
        try:
            from impacket.ldap import ldaptypes
            # Fix: Use ldap3 to get raw binary blob, then impacket.ldap.ldaptypes to parse
            sd_bytes = None
            if isinstance(raw_sd, (bytes, bytearray)):
                sd_bytes = bytes(raw_sd)
            elif hasattr(raw_sd, "raw_values") and raw_sd.raw_values:
                sd_bytes = raw_sd.raw_values[0]
            elif hasattr(raw_sd, "value") and raw_sd.value:
                sd_bytes = raw_sd.value

            if not sd_bytes:
                return issues

            sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
            sd.fromString(sd_bytes)

            if not sd.get("Dacl"):
                return issues

            for ace in sd["Dacl"]["Data"]:
                if ace["TypeName"] not in ("ACCESS_ALLOWED_ACE", "ACCESS_ALLOWED_OBJECT_ACE"):
                    continue
                mask = ace["Ace"]["Mask"]["Mask"]
                sid_obj = ace["Ace"]["Sid"]
                sid_str = sid_obj.formatCanonical()

                # Skip well-known admin SIDs
                SKIP_SIDS = {
                    "S-1-5-18",       # SYSTEM
                    "S-1-5-32-544",   # Administrators
                    "S-1-5-32-512",   # Domain Admins (well-known)
                }
                if sid_str in SKIP_SIDS:
                    continue

                RIGHT_MAP = {
                    0xF01FF: "GenericAll",
                    0x40000: "WriteDACL",
                    0x80000: "WriteOwner",
                    0x20000: "WriteProperty",
                    0x10000: "DeleteChild",
                }
                for mask_val, right_name in RIGHT_MAP.items():
                    if mask & mask_val == mask_val:
                        issues.append({"trustee": sid_str, "right": right_name})
                        break
                # AllExtendedRights
                if mask & 0x100:
                    issues.append({"trustee": sid_str, "right": "AllExtendedRights"})
        except ImportError:
            pass
        except Exception as exc:
            self.log.debug("SD parse error on %s: %s", dn, exc)
        return issues


class TestAclScanner:
    def test_dangerous_rights(self) -> None:
        assert "GenericAll"      in DANGEROUS_RIGHTS
        assert "WriteDACL"       in DANGEROUS_RIGHTS
        assert "WriteOwner"      in DANGEROUS_RIGHTS
        assert "AllExtendedRights" in DANGEROUS_RIGHTS

    def test_skip_sids(self) -> None:
        assert "S-1-5-18" in SKIP_SIDS    # SYSTEM
        assert "S-1-5-32-544" in SKIP_SIDS  # Administrators

    def test_phase(self) -> None:
        assert AclScanner.PHASE == 9

    def test_mitre(self) -> None:
        assert "mitre-T1484.001" in AclScanner.TAGS
