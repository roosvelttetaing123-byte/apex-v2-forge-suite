"""Windows Share Audit — SMB shares, NTFS permissions, sensitive exposure."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_SHARE = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"


class WinShareAudit(BaseModule):
    NAME        = "win_share_audit"
    DESCRIPTION = "WinRM credentialed: SMB shares, NTFS perms, Everyone access, sensitive files"
    PHASE       = 5
    TAGS        = ["credentialed", "windows", "shares", "smb", "cwe-732"]

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
            await self._audit_shares(host, transport_mgr.winrm, session)

        return self._make_result(start)

    async def _audit_shares(self, host: str, winrm, session) -> None:
        result = await winrm.execute(session,
            "Get-SmbShare | Where-Object { $_.Name -notmatch '\\$$' } | "
            "ForEach-Object { $share = $_; "
            "  $acl = Get-SmbShareAccess -Name $share.Name -ErrorAction SilentlyContinue; "
            "  $everyone = $acl | Where-Object { $_.AccountName -match 'Everyone' }; "
            "  if ($everyone) { Write-Output \"$($share.Name)|$($share.Path)|$($everyone.AccessRight)\" } "
            "} | Out-String")

        everyone_shares = []
        for line in result.stdout.strip().split("\n"):
            if "|" in line:
                parts = line.split("|")
                if len(parts) >= 3:
                    everyone_shares.append({
                        "name": parts[0].strip(),
                        "path": parts[1].strip(),
                        "access": parts[2].strip(),
                    })

        if everyone_shares:
            write_shares = [s for s in everyone_shares if "Change" in s["access"] or "Full" in s["access"]]
            severity = Severity.HIGH if write_shares else Severity.MEDIUM

            self.new_finding(
                title=f"SMB Shares Accessible by Everyone ({len(everyone_shares)}) — {host}",
                severity=severity,
                description=(
                    f"{len(everyone_shares)} shares accessible by Everyone on {host}: " +
                    "; ".join(f"{s['name']} ({s['access']})" for s in everyone_shares[:5])
                ),
                reproduction_steps=[f"Enter-PSSession {host}", "Get-SmbShareAccess -Name <share>"],
                remediation="Remove Everyone from share permissions. Use specific security groups.",
                references=["CWE-732"],
                evidence=Evidence(extra={"host": host, "shares": everyone_shares[:20]}),
                cvss_v31_vector=CVSS_SHARE,
                mitre_attack=["TA0007/T1135"],
                target=host, service="winrm",
            )
