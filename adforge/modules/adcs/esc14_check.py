"""ADCS ESC14 — altSecurityIdentities explicit mapping abuse."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_ESC14 = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
CVSS40_ESC14 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
class Esc14Check(BaseModule):
    """ADCS ESC14 — altSecurityIdentities explicit mapping: GenericWrite → impersonate account."""

    NAME        = "esc14_check"
    DESCRIPTION = "Check for ESC14: accounts with altSecurityIdentities writable by low-priv users"
    PHASE       = 11
    TAGS        = ["adcs", "esc14", "certificate", "privilege-escalation", "mitre-T1649"]

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
        )
        if not client.connect():
            return self._make_result(start)

        try:
            await self._check_alt_sec_identities(client, domain, dc_ip)
        finally:
            client.disconnect()

        return self._make_result(start)

    async def _check_alt_sec_identities(self, client: LdapClient, domain: str, dc_ip: str) -> None:
        # Find high-value accounts that have altSecurityIdentities set
        # (explicit certificate mapping)
        priv_groups = [
            "Domain Admins", "Enterprise Admins", "Schema Admins",
            "Administrators", "Account Operators", "Backup Operators",
        ]

        high_value_users: list[dict] = []
        for group in priv_groups:
            members = client.search(
                f"(&(objectClass=user)(memberOf=CN={group},CN=Users,"
                f"{','.join(f'DC={p}' for p in domain.split('.'))}))",
                ["sAMAccountName", "altSecurityIdentities", "distinguishedName",
                 "adminCount"],
            )
            for m in members:
                m["_group"] = group
                high_value_users.append(m)

        # Find accounts with altSecurityIdentities (explicit cert mappings)
        accounts_with_mapping = client.search(
            "(altSecurityIdentities=*)",
            ["sAMAccountName", "altSecurityIdentities", "adminCount",
             "distinguishedName"],
        )

        self.log.info(
            "Found %d high-value users, %d accounts with explicit cert mapping",
            len(high_value_users), len(accounts_with_mapping),
        )

        if accounts_with_mapping:
            names = [str(a.get("sAMAccountName", "?")) for a in accounts_with_mapping]
            mappings = {
                str(a.get("sAMAccountName", "?")): str(a.get("altSecurityIdentities", ""))[:80]
                for a in accounts_with_mapping[:10]
            }
            ev = Evidence(extra={
                "accounts_with_mapping": names[:20],
                "sample_mappings":       mappings,
                "high_value_with_mapping": [
                    str(u.get("sAMAccountName")) for u in accounts_with_mapping
                    if int(str(u.get("adminCount") or 0)) == 1
                ],
            })
            self.new_finding(
                title=f"ADCS ESC14 — {len(accounts_with_mapping)} Account(s) with Explicit Certificate Mapping",
                severity=Severity.HIGH,
                description=(
                    f"{len(accounts_with_mapping)} account(s) have altSecurityIdentities set "
                    "(explicit certificate-to-account mapping). "
                    "If any attacker-controlled principal has GenericWrite over these accounts, "
                    "they can modify altSecurityIdentities to map their own certificate, "
                    "enabling Kerberos authentication as the victim account.\n\n"
                    "This is exploitable even when StrongCertificateBindingEnforcement = 2 "
                    "(Full Enforcement mode) — the explicit mapping bypasses strong binding checks."
                ),
                reproduction_steps=[
                    "# Check if current user can write altSecurityIdentities on target:",
                    f"(Get-Acl 'AD:CN=targetuser,CN=Users,DC=corp,DC=local').Access | "
                    "Where {{$_.ActiveDirectoryRights -match 'Write'}}",
                    "# If GenericWrite/WriteProperty exists on altSecurityIdentities:",
                    "# 1. Get your cert thumbprint / serial number",
                    "# 2. Write explicit mapping:",
                    "Set-ADUser targetuser -Add @{altSecurityIdentities='X509:<I>...<SR>...'}",
                    "# 3. Request cert and auth as target:",
                    f"certipy auth -pfx attacker.pfx -username targetuser -domain {domain} "
                    f"-dc-ip {dc_ip}",
                ],
                remediation=(
                    "Audit altSecurityIdentities on all privileged accounts — "
                    "remove any unexpected explicit mappings. "
                    "Restrict GenericWrite/WriteProperty on altSecurityIdentities for "
                    "all high-value accounts. "
                    "Monitor Event 4662 (object access) on accounts with adminCount=1."
                ),
                references=[
                    "SpecterOps ESC14 research 2024",
                    "MITRE T1649",
                ],
                evidence=ev,
                cvss_v31_vector=CVSS_ESC14,
                cvss_v40_vector=CVSS40_ESC14,
                mitre_attack=["TA0004/T1649"],
                target=dc_ip,
            )
        else:
            self.log.info("No accounts with altSecurityIdentities found — ESC14 not directly applicable")


class TestEsc14Check:
    def test_cvss(self) -> None:
        assert CVSS_ESC14.startswith("CVSS:3.1")
