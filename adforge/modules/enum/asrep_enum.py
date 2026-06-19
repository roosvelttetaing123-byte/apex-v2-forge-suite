"""AS-REP Enum — enumerate accounts with Kerberos pre-auth disabled."""
from __future__ import annotations
import sys, time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_ASREP = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_ASREP = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
UAC_DONT_REQUIRE_PREAUTH = 0x400000

class AsrepEnum(BaseModule):
    NAME = "asrep_enum"
    DESCRIPTION = "Enumerate AS-REP roastable accounts (pre-auth disabled)"
    PHASE = 2
    TAGS = ["enum", "kerberos", "asrep", "cwe-287"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        domain = self.config.extra.get("domain", "")
        dc_ip = self.config.extra.get("dc", self.config.target)
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
            await self.rate_limit()
            # LDAP filter: enabled accounts with UF_DONT_REQUIRE_PREAUTH set
            users = client.search(
                "(&(objectCategory=person)(objectClass=user)"
                "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                ["sAMAccountName", "userPrincipalName", "adminCount", "description"],
            )

            if users:
                accounts = []
                for u in users:
                    name = str(u.get("sAMAccountName", "?"))
                    upn = str(u.get("userPrincipalName", "") or "")
                    priv = int(str(u.get("adminCount", 0) or 0)) == 1
                    accounts.append({"name": name, "upn": upn, "privileged": priv})

                priv_count = sum(1 for a in accounts if a["privileged"])
                ev = Evidence(extra={"accounts": accounts[:30], "privileged": priv_count})
                self.new_finding(
                    title=f"AS-REP Roastable Accounts — {len(accounts)} users (pre-auth disabled)",
                    severity=Severity.HIGH,
                    description=(
                        f"{len(accounts)} account(s) have Kerberos pre-authentication disabled:\n"
                        + "\n".join(
                            f"  {a['name']}" + (" [PRIVILEGED]" if a['privileged'] else "")
                            for a in accounts[:15]
                        )
                        + "\n\nThese accounts can be AS-REP Roasted WITHOUT any credentials."
                    ),
                    reproduction_steps=[
                        f"impacket-GetNPUsers {domain}/ -no-pass -usersfile users.txt -dc-ip {dc_ip}",
                        "hashcat -m 18200 hashes.txt rockyou.txt",
                    ],
                    remediation="Enable Kerberos pre-authentication on ALL accounts.",
                    references=["CWE-287", "MITRE T1558.004"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_ASREP, cvss_v40_vector=CVSS40_ASREP,
                    mitre_attack=["TA0006/T1558.004"],
                    target=dc_ip,
                )
                self.config.extra["asrep_accounts"] = [a["name"] for a in accounts]
        finally:
            client.disconnect()
        return self._make_result(start)

class TestAsrepEnum:
    def test_uac(self) -> None:
        assert UAC_DONT_REQUIRE_PREAUTH == 0x400000
    def test_phase(self) -> None:
        assert AsrepEnum.PHASE == 2
