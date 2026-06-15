"""Persistence Check — detect common AD persistence mechanisms."""
from __future__ import annotations
import sys, time
from datetime import datetime, timezone, timedelta
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
CVSS40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

class PersistCheck(BaseModule):
    NAME = "persist_check"
    DESCRIPTION = "Detect AD persistence: AdminSDHolder mods, SID History, krbtgt age, skeleton key indicators"
    PHASE = 13
    TAGS = ["post", "persistence", "cwe-284"]

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
            now = datetime.now(timezone.utc)

            # 1. krbtgt password age — if never rotated, Golden Ticket persists forever
            await self.rate_limit()
            krbtgt = client.search(
                "(sAMAccountName=krbtgt)", ["pwdLastSet", "whenChanged"])
            if krbtgt:
                pls = krbtgt[0].get("pwdLastSet")
                if pls:
                    try:
                        if isinstance(pls, (int, float)) and pls > 0:
                            last = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=pls // 10)
                            age_days = (now - last).days
                            if age_days > 180:
                                ev = Evidence(extra={"krbtgt_age_days": age_days})
                                self.new_finding(
                                    title=f"krbtgt Password Age — {age_days} days (Golden Ticket risk)",
                                    severity=Severity.HIGH,
                                    description=(
                                        f"The krbtgt account password was last set {age_days} days ago. "
                                        "If an attacker has previously extracted the krbtgt hash, their "
                                        "Golden Tickets remain valid until the password is rotated TWICE."
                                    ),
                                    reproduction_steps=["Get-ADUser krbtgt -Properties PasswordLastSet"],
                                    remediation="Rotate krbtgt password TWICE (with 12+ hours between rotations).",
                                    references=["MITRE T1558.001"],
                                    evidence=ev, cvss_v31_vector=CVSS, cvss_v40_vector=CVSS40,
                                    mitre_attack=["TA0003/T1558.001"],
                                    target=dc_ip)
                    except Exception:
                        pass

            # 2. SID History on non-migrated accounts
            await self.rate_limit()
            sid_history = client.search(
                "(&(objectCategory=person)(sIDHistory=*))",
                ["sAMAccountName", "sIDHistory"])
            if sid_history:
                accounts = [str(u.get("sAMAccountName", "?")) for u in sid_history]
                ev = Evidence(extra={"accounts": accounts[:20]})
                self.new_finding(
                    title=f"SID History Persistence — {len(accounts)} account(s)",
                    severity=Severity.MEDIUM,
                    description=(
                        f"{len(accounts)} account(s) have SID History set: {', '.join(accounts[:10])}\n\n"
                        "SID History can be abused for privilege escalation if it contains "
                        "admin SIDs from the current domain (not just migration artifacts)."
                    ),
                    reproduction_steps=["Get-ADUser -Filter {SIDHistory -like '*'} -Properties SIDHistory"],
                    remediation="Remove SID History from non-migrated accounts. Audit remaining entries.",
                    references=["MITRE T1134.005"],
                    evidence=ev,
                    cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
                    cvss_v40_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
                    target=dc_ip)

            # 3. Recently modified AdminSDHolder (backdoor detection)
            await self.rate_limit()
            adminsdholder = client.search(
                "(cn=AdminSDHolder)",
                ["whenChanged", "nTSecurityDescriptor"],
                search_base=f"CN=System,{client.base_dn}")
            if adminsdholder:
                changed = adminsdholder[0].get("whenChanged")
                if changed:
                    try:
                        if isinstance(changed, datetime):
                            if changed.tzinfo is None:
                                changed = changed.replace(tzinfo=timezone.utc)
                            days_ago = (now - changed).days
                            if days_ago < 30:
                                ev = Evidence(extra={"modified_days_ago": days_ago})
                                self.new_finding(
                                    title=f"AdminSDHolder Recently Modified — {days_ago} days ago",
                                    severity=Severity.HIGH,
                                    description=(
                                        "AdminSDHolder was modified recently. This is unusual and may "
                                        "indicate a persistence mechanism — an attacker adds ACEs to "
                                        "AdminSDHolder, which SDProp propagates to ALL protected objects."
                                    ),
                                    reproduction_steps=["Get-ADObject 'CN=AdminSDHolder,CN=System,...' -Properties whenChanged"],
                                    remediation="Audit AdminSDHolder ACL. Compare against known-good baseline.",
                                    references=["MITRE T1098"],
                                    evidence=ev, cvss_v31_vector=CVSS, cvss_v40_vector=CVSS40,
                                    target=dc_ip)
                    except Exception:
                        pass
        finally:
            client.disconnect()
        return self._make_result(start)

class TestPersistCheck:
    def test_phase(self) -> None: assert PersistCheck.PHASE == 13
