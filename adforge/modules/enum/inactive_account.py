"""Inactive Account Detection — find stale/unused accounts for cleanup."""
from __future__ import annotations
import sys, time
from datetime import datetime, timezone, timedelta
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity
from adforge.core.ldap_client import LdapClient

CVSS_INACTIVE = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"
CVSS40_INACTIVE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
INACTIVE_DAYS = 90

class InactiveAccount(BaseModule):
    NAME = "inactive_account"
    DESCRIPTION = "Find inactive/stale accounts that should be disabled"
    PHASE = 2
    TAGS = ["enum", "hygiene", "ldap", "cwe-672"]

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
            # Only enabled accounts
            users = client.search(
                "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                ["sAMAccountName", "lastLogonTimestamp", "pwdLastSet", "adminCount", "whenCreated"],
            )

            now = datetime.now(timezone.utc)
            cutoff = now - timedelta(days=INACTIVE_DAYS)
            inactive = []

            for u in users:
                name = str(u.get("sAMAccountName", "?"))
                last_logon = u.get("lastLogonTimestamp")
                admin = int(str(u.get("adminCount", 0) or 0))

                if last_logon:
                    try:
                        if isinstance(last_logon, (int, float)) and last_logon > 0:
                            ll = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=last_logon // 10)
                            if ll < cutoff:
                                inactive.append({
                                    "name": name, "days": (now - ll).days,
                                    "privileged": admin == 1,
                                })
                    except Exception:
                        pass

            if inactive:
                priv_inactive = [a for a in inactive if a["privileged"]]
                inactive.sort(key=lambda x: -x["days"])
                severity = Severity.HIGH if priv_inactive else Severity.MEDIUM

                ev = Evidence(extra={"inactive": inactive[:30], "privileged_inactive": len(priv_inactive)})
                self.new_finding(
                    title=f"Inactive Accounts — {len(inactive)} enabled accounts unused >{INACTIVE_DAYS}d",
                    severity=severity,
                    description=(
                        f"{len(inactive)} enabled accounts have not logged in for {INACTIVE_DAYS}+ days:\n"
                        + "\n".join(f"  {a['name']} ({a['days']}d)" + (" [PRIVILEGED]" if a['privileged'] else "") for a in inactive[:10])
                        + (f"\n\n{len(priv_inactive)} PRIVILEGED accounts are inactive." if priv_inactive else "")
                    ),
                    reproduction_steps=["Get-ADUser -Filter {Enabled -eq $true -and LastLogonDate -lt (Get-Date).AddDays(-90)}"],
                    remediation=f"Disable accounts inactive for >{INACTIVE_DAYS} days. Review privileged accounts immediately.",
                    references=["CWE-672", "NIST SP 800-53 AC-2"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_INACTIVE, cvss_v40_vector=CVSS40_INACTIVE,
                    target=dc_ip,
                )
        finally:
            client.disconnect()
        return self._make_result(start)

class TestInactiveAccount:
    def test_days(self) -> None:
        assert INACTIVE_DAYS == 90
    def test_phase(self) -> None:
        assert InactiveAccount.PHASE == 2
