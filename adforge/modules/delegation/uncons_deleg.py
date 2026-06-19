"""Unconstrained delegation checker — find computers/users with unconstrained delegation."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_UNCONS = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS40_UNCONS = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
# UAC flags
ADS_UF_TRUSTED_FOR_DELEGATION = 0x80000


class UnconsDeleg(BaseModule):
    """Unconstrained Kerberos delegation scanner."""

    NAME        = "uncons_deleg"
    DESCRIPTION = "Find computers and users with unconstrained Kerberos delegation enabled"
    PHASE       = 8
    TAGS        = ["delegation", "kerberos", "unconstrained", "mitre-T1550.003"]

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
        )

        if not client.connect():
            return self._make_result(start)

        try:
            # Find computers with unconstrained delegation (excluding DCs)
            computers = client.search(
                "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
                ["sAMAccountName", "dNSHostName", "userAccountControl", "operatingSystem"],
            )

            # Find users with unconstrained delegation
            users = client.search(
                "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=524288))",
                ["sAMAccountName", "distinguishedName", "userAccountControl"],
            )

            # Filter out DCs using the reliable UAC SERVER_TRUST_ACCOUNT flag (0x2000).
            # OS-name and OU-name checks are fragile (custom OUs, non-English OSes).
            DC_UAC_FLAG = 0x2000  # ADS_UF_SERVER_TRUST_ACCOUNT — set on DC machine accounts
            non_dc_computers = [
                c for c in computers
                if not (int(str(c.get("userAccountControl") or 0)) & DC_UAC_FLAG)
            ]

            if non_dc_computers:
                names = [c.get("sAMAccountName", "?") for c in non_dc_computers]
                self.config.extra["uncons_deleg_computers"] = names
                ev = Evidence(
                    extra={
                        "computers": [c.get("sAMAccountName", "?") for c in non_dc_computers],
                        "dns_names": [c.get("dNSHostName", "?") for c in non_dc_computers],
                    }
                )
                self.new_finding(
                    title=f"Unconstrained Delegation — {len(non_dc_computers)} Computer(s)",
                    severity=Severity.HIGH,
                    description=(
                        f"{len(non_dc_computers)} non-DC computer(s) have unconstrained delegation: "
                        f"{', '.join(names[:10])}. "
                        "If compromised, an attacker can coerce DCs to authenticate to this host "
                        "(via PrintSpooler, PetitPotam, etc.) and steal TGTs for DCSync/etc."
                    ),
                    reproduction_steps=[
                        "# On host with unconstrained delegation as admin:",
                        "rubeus.exe monitor /interval:5 /nowrap",
                        "# Trigger DC auth: Invoke-SpoolSample dc.corp.local server.corp.local",
                        "# Extract TGT from memory and use for further attacks",
                    ],
                    remediation=(
                        "Replace unconstrained delegation with constrained delegation. "
                        "Use Resource-Based Constrained Delegation (RBCD) where possible. "
                        "Enable 'Account is sensitive and cannot be delegated' on DA accounts."
                    ),
                    references=["MITRE T1550.003", "adsecurity.org unconstrained delegation"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_UNCONS,
                    cvss_v40_vector=CVSS40_UNCONS,
                    mitre_attack=["TA0006/T1550.003"],
                    target=dc_ip,
                )

            if users:
                user_names = [u.get("sAMAccountName", "?") for u in users]
                ev = Evidence(extra={"users": user_names})
                self.new_finding(
                    title=f"Unconstrained Delegation on User Accounts ({len(users)} users)",
                    severity=Severity.HIGH,
                    description=(
                        f"User account(s) with unconstrained delegation: {', '.join(user_names[:10])}. "
                        "User accounts with unconstrained delegation are unusual and high risk."
                    ),
                    reproduction_steps=["Check UAC: TRUSTED_FOR_DELEGATION flag"],
                    remediation="Remove unconstrained delegation from user accounts.",
                    references=["MITRE T1550.003"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_UNCONS,
                    cvss_v40_vector=CVSS40_UNCONS,
                    target=dc_ip,
                )

        finally:
            client.disconnect()

        return self._make_result(start)


class TestUnconsDeleg:
    def test_uac_flag(self) -> None:
        assert ADS_UF_TRUSTED_FOR_DELEGATION == 0x80000
