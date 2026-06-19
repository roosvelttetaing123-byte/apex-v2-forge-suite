"""SPN enumeration — find all service principal names in the domain."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient


class SpnEnum(BaseModule):
    """Service Principal Name (SPN) enumerator."""

    NAME        = "spn_enum"
    DESCRIPTION = "Enumerate all SPNs in the domain to identify Kerberoastable accounts"
    PHASE       = 2
    TAGS        = ["enum", "spn", "kerberoast", "ldap"]

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
            spn_accounts = client.search(
                "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))",
                ["sAMAccountName", "servicePrincipalName", "adminCount",
                 "memberOf", "pwdLastSet", "userAccountControl"],
            )

            self.log.info("Found %d SPN account(s)", len(spn_accounts))
            self.config.extra["spn_accounts"] = spn_accounts

            if spn_accounts:
                privileged_spns = [
                    a for a in spn_accounts
                    if int(str(a.get("adminCount", 0) or 0)) == 1
                ]

                ev = Evidence(
                    extra={
                        "total_spns":      len(spn_accounts),
                        "privileged_spns": len(privileged_spns),
                        "accounts":        [
                            {
                                "name": a.get("sAMAccountName"),
                                "spns": str(a.get("servicePrincipalName", ""))[:60],
                                "admin": bool(int(str(a.get("adminCount", 0) or 0))),
                            }
                            for a in spn_accounts[:10]
                        ],
                    }
                )
                self.new_finding(
                    title=f"Kerberoastable Accounts ({len(spn_accounts)} SPNs found)",
                    severity=Severity.MEDIUM if not privileged_spns else Severity.HIGH,
                    description=(
                        f"{len(spn_accounts)} user account(s) with SPNs (Kerberoastable). "
                        + (f"{len(privileged_spns)} of these have adminCount=1 (PRIVILEGED accounts). "
                           if privileged_spns else "")
                        + "These accounts can be Kerberoasted without triggering lockout."
                    ),
                    reproduction_steps=[
                        "Run kerberoast module to obtain TGS hashes",
                        f"GetUserSPNs.py {domain}/{self.config.extra.get('username', 'user')} -request -dc-ip {dc_ip}",
                    ],
                    remediation=(
                        "Use gMSA for service accounts — passwords auto-rotate and are 120 chars. "
                        "Remove SPNs from high-privilege accounts. "
                        "Set 25+ char random passwords on all service accounts with SPNs."
                    ),
                    references=["MITRE T1558.003"],
                    evidence=ev,
                    cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    mitre_attack=["TA0006/T1558.003"],
                    target=dc_ip,
                )
        finally:
            client.disconnect()

        return self._make_result(start)


class TestSpnEnum:
    def test_name(self) -> None:
        assert SpnEnum.NAME == "spn_enum"
