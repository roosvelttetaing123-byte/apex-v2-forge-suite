"""Windows Scheduled Task Audit — SYSTEM tasks, writable binaries, suspicious authors."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_SCHTASK = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"


class WinScheduledTask(BaseModule):
    NAME        = "win_scheduled_task"
    DESCRIPTION = "WinRM credentialed: scheduled tasks as SYSTEM, writable task binaries"
    PHASE       = 5
    TAGS        = ["credentialed", "windows", "scheduled_tasks", "privesc", "cwe-732"]

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
            await self._audit_tasks(host, transport_mgr.winrm, session)

        return self._make_result(start)

    async def _audit_tasks(self, host: str, winrm, session) -> None:
        result = await winrm.execute(session,
            "Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' } | "
            "ForEach-Object { $t = $_; $a = $t.Actions[0]; "
            "  $p = $t.Principal; "
            "  if ($p.UserId -match 'SYSTEM|LocalSystem') { "
            "    Write-Output \"$($t.TaskName)|$($a.Execute)|$($p.UserId)|$($t.Author)\" } "
            "} | Out-String")

        system_tasks = []
        for line in result.stdout.strip().split("\n"):
            if "|" in line:
                parts = line.split("|")
                if len(parts) >= 4:
                    system_tasks.append({
                        "name": parts[0].strip(),
                        "exe": parts[1].strip(),
                        "user": parts[2].strip(),
                        "author": parts[3].strip(),
                    })

        # Check for writable SYSTEM task binaries
        writable_tasks = []
        for task in system_tasks[:30]:
            exe_path = task["exe"]
            if not exe_path or exe_path.startswith("%"):
                continue
            check = await winrm.execute(session,
                f"if (Test-Path '{exe_path}') {{ "
                f"  $acl = Get-Acl '{exe_path}' -ErrorAction SilentlyContinue; "
                f"  $w = $acl.Access | Where-Object {{ "
                f"    $_.FileSystemRights -match 'Write|FullControl|Modify' -and "
                f"    $_.IdentityReference -match 'Everyone|Users|Authenticated' }}; "
                f"  if ($w) {{ 'WRITABLE' }} else {{ 'OK' }} }} else {{ 'MISSING' }}")

            if "WRITABLE" in check.stdout:
                writable_tasks.append(task)

        if writable_tasks:
            self.new_finding(
                title=f"Writable SYSTEM Scheduled Task Binaries ({len(writable_tasks)}) — {host}",
                severity=Severity.CRITICAL,
                description=(
                    f"{len(writable_tasks)} scheduled tasks run as SYSTEM with writable executables: " +
                    "; ".join(f"{t['name']} ({t['exe']})" for t in writable_tasks[:5])
                ),
                reproduction_steps=[f"Enter-PSSession {host}", "Get-ScheduledTask | Where State -eq Ready"],
                remediation="Fix permissions on task executables. Remove write access for non-admins.",
                references=["CWE-732"],
                evidence=Evidence(extra={"host": host, "tasks": writable_tasks[:20]}),
                cvss_v31_vector=CVSS_SCHTASK,
                mitre_attack=["TA0003/T1053.005", "TA0004/T1053.005"],
                target=host, service="winrm", confidence="HIGH",
            )

        # Non-Microsoft SYSTEM tasks (potential persistence)
        non_ms = [t for t in system_tasks if t["author"] and "Microsoft" not in t["author"]]
        if non_ms:
            self.new_finding(
                title=f"Non-Microsoft SYSTEM Scheduled Tasks ({len(non_ms)}) — {host}",
                severity=Severity.LOW,
                description=(
                    f"{len(non_ms)} non-Microsoft scheduled tasks run as SYSTEM: " +
                    "; ".join(f"{t['name']} by {t['author']}" for t in non_ms[:5])
                ),
                reproduction_steps=[f"Enter-PSSession {host}", "Get-ScheduledTask"],
                remediation="Audit non-Microsoft SYSTEM tasks for legitimacy.",
                references=["CWE-272"],
                evidence=Evidence(extra={"host": host, "tasks": non_ms[:20]}),
                mitre_attack=["TA0003/T1053.005"],
                target=host, service="winrm",
            )
