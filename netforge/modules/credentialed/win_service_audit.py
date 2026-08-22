"""Windows Service Audit — unquoted paths, writable binaries, SYSTEM services."""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_UNQUOTED = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
CVSS_WRITABLE = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"


class WinServiceAudit(BaseModule):
    NAME        = "win_service_audit"
    DESCRIPTION = "WinRM credentialed: unquoted service paths, writable binaries, SYSTEM services"
    PHASE       = 5
    TAGS        = ["credentialed", "windows", "services", "privesc", "cwe-428"]

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
            await self._audit_services(host, transport_mgr.winrm, session)

        return self._make_result(start)

    async def _audit_services(self, host: str, winrm, session) -> None:
        # Unquoted service paths
        unquoted_result = await winrm.execute(session,
            "Get-WmiObject Win32_Service | Where-Object { "
            "$_.PathName -notmatch '^\"|^''' -and $_.PathName -match ' ' -and "
            "$_.PathName -notmatch '^C:\\\\Windows\\\\system32' } | "
            "Select-Object Name,PathName,StartMode | Format-Table -AutoSize | Out-String -Width 300")

        unquoted = []
        for line in unquoted_result.stdout.split("\n"):
            line = line.strip()
            if line and not line.startswith("-") and "Name" not in line and "PathName" not in line:
                parts = line.split(None, 1)
                if len(parts) >= 2:
                    unquoted.append({"name": parts[0], "path": parts[1][:150]})

        if unquoted:
            self.new_finding(
                title=f"Unquoted Service Paths ({len(unquoted)}) — Privesc — {host}",
                severity=Severity.HIGH,
                description=(
                    f"{len(unquoted)} services have unquoted paths with spaces on {host}. "
                    "Place a binary in the path prefix to hijack service execution. "
                    f"Examples: " + "; ".join(f"{u['name']}: {u['path']}" for u in unquoted[:3])
                ),
                reproduction_steps=[
                    f"Enter-PSSession {host}",
                    "Get-WmiObject Win32_Service | Where PathName -notmatch '\"'",
                ],
                remediation='Quote service paths: sc config <svc> binPath= "\\\"C:\\path with spaces\\svc.exe\\\""',
                references=["CWE-428"],
                evidence=Evidence(extra={"host": host, "unquoted": unquoted[:20]}),
                cvss_v31_vector=CVSS_UNQUOTED,
                mitre_attack=["TA0004/T1574.009"],
                target=host, service="winrm", confidence="HIGH",
            )

        # Services with writable binary paths
        writable_result = await winrm.execute(session,
            "$services = Get-WmiObject Win32_Service | Where-Object { $_.State -eq 'Running' }; "
            "foreach ($s in $services) { "
            "  $path = ($s.PathName -replace '\"','').Split(' ')[0]; "
            "  if (Test-Path $path) { "
            "    $acl = Get-Acl $path -ErrorAction SilentlyContinue; "
            "    $writable = $acl.Access | Where-Object { "
            "      $_.FileSystemRights -match 'Write|FullControl|Modify' -and "
            "      $_.IdentityReference -match 'Everyone|Users|Authenticated' }; "
            "    if ($writable) { Write-Output \"$($s.Name)|$path\" } } }"
        )

        writable_svcs = []
        for line in writable_result.stdout.strip().split("\n"):
            if "|" in line:
                parts = line.split("|", 1)
                writable_svcs.append({"name": parts[0], "path": parts[1]})

        if writable_svcs:
            self.new_finding(
                title=f"Writable Service Binaries ({len(writable_svcs)}) — {host}",
                severity=Severity.CRITICAL,
                description=(
                    f"{len(writable_svcs)} running services have writable binaries: "
                    + "; ".join(f"{s['name']}" for s in writable_svcs[:5])
                ),
                reproduction_steps=[f"Enter-PSSession {host}", "Get-Acl <service_binary>"],
                remediation="Remove write permissions for non-admin users on service binaries.",
                references=["CWE-732"],
                evidence=Evidence(extra={"host": host, "services": writable_svcs[:20]}),
                cvss_v31_vector=CVSS_WRITABLE,
                mitre_attack=["TA0004/T1574.010"],
                target=host, service="winrm", confidence="HIGH",
            )
