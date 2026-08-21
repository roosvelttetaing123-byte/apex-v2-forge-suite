"""Windows Patch Audit — credentialed WinRM check for missing KBs/patches.

Nessus equivalent: Plugin 38153 (Microsoft Windows Missing Patches).
Queries Get-HotFix and wmic qfe, maps missing KBs to CVEs.
"""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_PATCH_CRIT = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS_PATCH_HIGH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"

# Critical Windows CVEs and their fix KBs (sample — real scanners maintain massive databases)
CRITICAL_KB_MAP = {
    "KB5034441": ("CVE-2024-20666", "BitLocker bypass", 9.8),
    "KB5034763": ("CVE-2024-21351", "SmartScreen bypass", 8.8),
    "KB5035845": ("CVE-2024-21338", "Windows Kernel EoP", 7.8),
    "KB5039211": ("CVE-2024-30080", "MSMQ RCE", 9.8),
    "KB5005565": ("CVE-2021-34527", "PrintNightmare", 8.8),
    "KB5004945": ("CVE-2021-34527", "PrintNightmare P2", 8.8),
    "KB5003637": ("CVE-2021-31166", "HTTP.sys RCE", 9.8),
    "KB5001347": ("CVE-2021-26855", "ProxyLogon", 9.8),
    "KB4577051": ("CVE-2020-1472", "Zerologon", 10.0),
    "KB4571756": ("CVE-2020-1472", "Zerologon P2", 10.0),
    "KB4534271": ("CVE-2020-0601", "CurveBall/CryptoAPI", 8.1),
    "KB4012212": ("CVE-2017-0143", "EternalBlue MS17-010", 9.8),
}


class WinPatchAudit(BaseModule):
    NAME        = "win_patch_audit"
    DESCRIPTION = "WinRM credentialed: missing Windows patches/KBs, CVE mapping"
    PHASE       = 5
    TAGS        = ["credentialed", "windows", "patch", "cve", "compliance"]

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
            await self._audit_patches(host, transport_mgr.winrm, session)

        return self._make_result(start)

    async def _audit_patches(self, host: str, winrm, session) -> None:
        # Get installed hotfixes
        result = await winrm.execute(session,
            "Get-HotFix | Select-Object -Property HotFixID,InstalledOn,Description | "
            "Sort-Object InstalledOn -Descending | Format-Table -AutoSize | Out-String -Width 200"
        )
        if not result.success:
            return

        installed_kbs = set()
        for line in result.stdout.split("\n"):
            m = re.search(r'(KB\d+)', line)
            if m:
                installed_kbs.add(m.group(1))

        # Check last patch date
        date_result = await winrm.execute(session,
            "Get-HotFix | Sort-Object InstalledOn -Descending | "
            "Select-Object -First 1 -ExpandProperty InstalledOn | Out-String"
        )
        last_patch = date_result.stdout.strip() if date_result.success else "unknown"

        # Check for missing critical KBs
        missing_critical = []
        for kb, (cve, desc, cvss) in CRITICAL_KB_MAP.items():
            if kb not in installed_kbs:
                missing_critical.append({"kb": kb, "cve": cve, "desc": desc, "cvss": cvss})

        # Get Windows Update status
        wu_result = await winrm.execute(session,
            "$Session = New-Object -ComObject Microsoft.Update.Session; "
            "$Searcher = $Session.CreateUpdateSearcher(); "
            "try { $Results = $Searcher.Search('IsInstalled=0'); "
            "$Results.Updates.Count } catch { 'error' }"
        )
        pending_count = 0
        try:
            pending_count = int(wu_result.stdout.strip())
        except (ValueError, TypeError):
            pass

        if missing_critical:
            worst_cvss = max(m["cvss"] for m in missing_critical)
            severity = Severity.CRITICAL if worst_cvss >= 9.0 else Severity.HIGH

            self.new_finding(
                title=f"Critical Windows Patches Missing ({len(missing_critical)}) — {host}",
                severity=severity,
                description=(
                    f"{len(missing_critical)} critical patches missing on {host}. "
                    f"Most critical: " +
                    "; ".join(f"{m['cve']} ({m['desc']}, CVSS {m['cvss']})" for m in missing_critical[:5])
                ),
                reproduction_steps=[
                    f"Enter-PSSession {host}",
                    "Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20",
                ],
                remediation="Apply Windows Updates immediately. Enable automatic updates.",
                references=[m["cve"] for m in missing_critical[:10]],
                evidence=Evidence(extra={
                    "host": host,
                    "missing_critical": missing_critical[:20],
                    "installed_count": len(installed_kbs),
                    "last_patch": last_patch,
                    "pending_updates": pending_count,
                }),
                cvss_v31_vector=CVSS_PATCH_CRIT,
                mitre_attack=["TA0001/T1190"],
                target=host, service="winrm", confidence="MEDIUM",
            )
        elif pending_count > 10:
            self.new_finding(
                title=f"Windows Updates Pending ({pending_count}) — {host}",
                severity=Severity.MEDIUM,
                description=f"{pending_count} Windows updates pending on {host}. Last patched: {last_patch}.",
                reproduction_steps=[f"Enter-PSSession {host}", "Get-HotFix | Measure-Object"],
                remediation="Schedule patch window and apply updates.",
                references=["CWE-1104"],
                evidence=Evidence(extra={"host": host, "pending": pending_count, "last_patch": last_patch}),
                cvss_v31_vector=CVSS_PATCH_HIGH,
                target=host, service="winrm",
            )
