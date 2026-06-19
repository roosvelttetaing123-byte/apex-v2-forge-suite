"""Service Account Audit — SPN accounts, encryption types, password age."""
from __future__ import annotations
import sys, time
from datetime import datetime, timezone, timedelta
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_SVC = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
CVSS40_SVC = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_INFO = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"
CVSS40_INFO = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

ETYPE_RC4 = 0x04
ETYPE_AES128 = 0x08
ETYPE_AES256 = 0x10

class ServiceAccountAudit(BaseModule):
    NAME = "service_account_audit"
    DESCRIPTION = "Audit service accounts: SPNs, encryption types, password age, privileges"
    PHASE = 2
    TAGS = ["enum", "service-accounts", "kerberoast", "cwe-521"]

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
            # User accounts with SPNs (kerberoastable)
            svc_accounts = client.search(
                "(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)"
                "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                ["sAMAccountName", "servicePrincipalName", "adminCount",
                 "pwdLastSet", "msDS-SupportedEncryptionTypes", "description"],
            )
            self.log.info("Found %d SPN-bearing user account(s)", len(svc_accounts))

            now = datetime.now(timezone.utc)
            accounts = []
            rc4_only = []
            old_password = []

            for acct in svc_accounts:
                name = str(acct.get("sAMAccountName", "?"))
                spns = acct.get("servicePrincipalName", [])
                if isinstance(spns, str):
                    spns = [spns]
                priv = int(str(acct.get("adminCount", 0) or 0)) == 1
                etypes = int(str(acct.get("msDS-SupportedEncryptionTypes", 0) or 0))

                # Password age
                pwd_age_days = None
                pls = acct.get("pwdLastSet")
                if pls:
                    try:
                        if isinstance(pls, (int, float)) and pls > 0:
                            last = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=pls // 10)
                            pwd_age_days = (now - last).days
                    except Exception:
                        pass

                info = {
                    "name": name, "spns": spns[:3], "privileged": priv,
                    "etypes": etypes, "rc4_only": etypes > 0 and not (etypes & (ETYPE_AES128 | ETYPE_AES256)),
                    "pwd_age_days": pwd_age_days,
                }
                accounts.append(info)

                if info["rc4_only"]:
                    rc4_only.append(name)
                if pwd_age_days and pwd_age_days > 365:
                    old_password.append({"name": name, "age": pwd_age_days})

            if accounts:
                priv_count = sum(1 for a in accounts if a["privileged"])
                ev = Evidence(extra={"accounts": accounts[:30], "privileged": priv_count})
                self.new_finding(
                    title=f"Kerberoastable Accounts — {len(accounts)} SPN users ({priv_count} privileged)",
                    severity=Severity.MEDIUM if not priv_count else Severity.HIGH,
                    description=(
                        f"{len(accounts)} user accounts with SPNs (Kerberoastable):\n"
                        + "\n".join(
                            f"  {a['name']}: {a['spns'][0] if a['spns'] else '?'}"
                            + (" [PRIVILEGED]" if a['privileged'] else "")
                            + (f" [RC4-ONLY]" if a['rc4_only'] else "")
                            + (f" [PWD: {a['pwd_age_days']}d]" if a['pwd_age_days'] else "")
                            for a in accounts[:10]
                        )
                    ),
                    reproduction_steps=[
                        f"impacket-GetUserSPNs {domain}/user:pass -dc-ip {dc_ip} -request",
                        "hashcat -m 13100 (RC4) or -m 19700 (AES) hashes.txt wordlist.txt",
                    ],
                    remediation=(
                        "1. Use gMSA for service accounts (auto-rotating 256-char passwords)\n"
                        "2. Set 30+ character passwords on legacy SPN accounts\n"
                        "3. Enable AES encryption: msDS-SupportedEncryptionTypes = 0x18\n"
                        "4. Remove SPNs from privileged accounts"
                    ),
                    references=["CWE-521", "MITRE T1558.003"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_SVC, cvss_v40_vector=CVSS40_SVC,
                    mitre_attack=["TA0006/T1558.003"],
                    target=dc_ip,
                )

            if rc4_only:
                ev = Evidence(extra={"rc4_accounts": rc4_only})
                self.new_finding(
                    title=f"RC4-Only Service Accounts — {len(rc4_only)} crackable in minutes",
                    severity=Severity.HIGH,
                    description=(
                        f"{len(rc4_only)} service accounts only support RC4 encryption: "
                        f"{', '.join(rc4_only[:10])}. "
                        "RC4 TGS tickets crack orders of magnitude faster than AES."
                    ),
                    reproduction_steps=["hashcat -m 13100 rc4_hashes.txt rockyou.txt"],
                    remediation="Enable AES: Set-ADUser -KerberosEncryptionType AES128,AES256",
                    references=["CWE-326"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_SVC, cvss_v40_vector=CVSS40_SVC,
                    target=dc_ip,
                )

            self.config.extra["spn_accounts"] = [a["name"] for a in accounts]
        finally:
            client.disconnect()
        return self._make_result(start)

class TestServiceAccountAudit:
    def test_etypes(self) -> None:
        assert ETYPE_RC4 == 0x04
        assert ETYPE_AES256 == 0x10
    def test_phase(self) -> None:
        assert ServiceAccountAudit.PHASE == 2
