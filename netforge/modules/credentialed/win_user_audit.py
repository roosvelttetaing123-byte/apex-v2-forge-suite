"""Windows User Audit — local admin enumeration, password policies, locked accounts."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_WEAK_PW = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS_ADMIN   = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"


class WinUserAudit(BaseModule):
    NAME        = "win_user_audit"
    DESCRIPTION = "WinRM credentialed: local admins, password policies, disabled accounts, never-expire"
    PHASE       = 5
    TAGS        = ["credentialed", "windows", "users", "passwords", "compliance"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        transport_mgr = self.config.extra.get("transport_manager")
        if not transport_mgr or not transport_mgr.has_creds("winrm"):
            return self._make_result(start, skipped=True, skip_reason="no WinRM credentials")

        hosts = self.config.extra.get("live_hosts", [self.config.target])
        for host in hosts[:20]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            session = await transport_mgr.get_winrm_session(host)
            if not session:
                continue
            await self._audit_users(host, transport_mgr.winrm, session)

        return self._make_result(start)

    async def _audit_users(self, host: str, winrm, session) -> None:
        # Local administrators
        admin_result = await winrm.execute(session,
            "Get-LocalGroupMember -Group 'Administrators' | Select-Object Name,ObjectClass | "
            "Format-Table -AutoSize | Out-String")

        admins = [l.strip().split()[0] for l in admin_result.stdout.split("\n")
                 if l.strip() and not l.startswith("-") and "Name" not in l and l.strip()]

        if len(admins) > 3:
            self.new_finding(
                title=f"Excessive Local Administrators ({len(admins)}) — {host}",
                severity=Severity.MEDIUM,
                description=f"{len(admins)} local admin accounts on {host}: {', '.join(admins[:10])}.",
                reproduction_steps=[f"Enter-PSSession {host}", "Get-LocalGroupMember -Group 'Administrators'"],
                remediation="Remove unnecessary admin accounts. Use least-privilege principle.",
                references=["CWE-250", "CIS Benchmark 1.1"],
                evidence=Evidence(extra={"host": host, "admins": admins[:20]}),
                cvss_v31_vector=CVSS_ADMIN,
                target=host, service="winrm",
            )

        # Password policy
        policy_result = await winrm.execute(session, "net accounts | Out-String")
        if policy_result.success:
            policy = policy_result.stdout
            issues = []
            for line in policy.split("\n"):
                if "Minimum password length" in line:
                    try:
                        val = int(line.split(":")[-1].strip())
                        if val < 12:
                            issues.append(f"Min password length: {val} (should be 12+)")
                    except ValueError:
                        pass
                if "Maximum password age" in line and "Unlimited" in line:
                    issues.append("Password never expires")
                if "Lockout threshold" in line:
                    try:
                        val = int(line.split(":")[-1].strip())
                        if val == 0 or val > 10:
                            issues.append(f"Lockout threshold: {val} (should be 3-5)")
                    except ValueError:
                        if "Never" in line:
                            issues.append("No account lockout configured")

            if issues:
                self.new_finding(
                    title=f"Weak Password Policy — {host}",
                    severity=Severity.HIGH,
                    description=f"Password policy issues on {host}: {'; '.join(issues)}.",
                    reproduction_steps=[f"Enter-PSSession {host}", "net accounts"],
                    remediation="Configure: Min length 12+, max age 90 days, lockout after 5 attempts.",
                    references=["CWE-521", "CIS Benchmark 1.1"],
                    evidence=Evidence(extra={"host": host, "issues": issues, "raw": policy[:500]}),
                    cvss_v31_vector=CVSS_WEAK_PW,
                    target=host, service="winrm",
                )

        # Users with password never expires
        never_expire = await winrm.execute(session,
            "Get-LocalUser | Where-Object {$_.PasswordNeverExpires -eq $true -and $_.Enabled -eq $true} | "
            "Select-Object Name | Format-Table -AutoSize | Out-String")
        expire_users = [l.strip() for l in never_expire.stdout.split("\n")
                       if l.strip() and "Name" not in l and "-" not in l[:5]]
        if expire_users:
            self.new_finding(
                title=f"Accounts With Non-Expiring Passwords ({len(expire_users)}) — {host}",
                severity=Severity.MEDIUM,
                description=f"{len(expire_users)} enabled accounts have non-expiring passwords: {', '.join(expire_users[:10])}.",
                reproduction_steps=[f"Enter-PSSession {host}", "Get-LocalUser | Where PasswordNeverExpires"],
                remediation="Set PasswordNeverExpires to $false for all non-service accounts.",
                references=["CWE-262"],
                evidence=Evidence(extra={"host": host, "users": expire_users[:20]}),
                target=host, service="winrm",
            )
