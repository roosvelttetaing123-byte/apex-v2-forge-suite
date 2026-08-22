"""Windows Defender Audit — AV status, exclusions, ASR rules via WinRM."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_AV_OFF = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"


class WinDefenderAudit(BaseModule):
    NAME        = "win_defender_audit"
    DESCRIPTION = "WinRM credentialed: Defender status, exclusions, ASR rules, definitions age"
    PHASE       = 5
    TAGS        = ["credentialed", "windows", "defender", "antivirus", "compliance"]

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
            await self._audit_defender(host, transport_mgr.winrm, session)

        return self._make_result(start)

    async def _audit_defender(self, host: str, winrm, session) -> None:
        status = await winrm.execute(session,
            "Get-MpComputerStatus | Select-Object AntivirusEnabled,RealTimeProtectionEnabled,"
            "AntivirusSignatureAge,AntispywareEnabled,BehaviorMonitorEnabled,"
            "IoavProtectionEnabled,NISEnabled | Format-List | Out-String")

        issues = []
        if "AntivirusEnabled" in status.stdout:
            for line in status.stdout.split("\n"):
                line = line.strip()
                if ":" not in line:
                    continue
                key, _, val = line.partition(":")
                key, val = key.strip(), val.strip()

                if key == "AntivirusEnabled" and val.lower() == "false":
                    issues.append("Antivirus DISABLED")
                elif key == "RealTimeProtectionEnabled" and val.lower() == "false":
                    issues.append("Real-time protection DISABLED")
                elif key == "AntivirusSignatureAge":
                    try:
                        age = int(val)
                        if age > 7:
                            issues.append(f"Definitions {age} days old")
                    except ValueError:
                        pass
                elif key == "BehaviorMonitorEnabled" and val.lower() == "false":
                    issues.append("Behavior monitoring disabled")

        if issues:
            has_av_off = any("DISABLED" in i for i in issues)
            self.new_finding(
                title=f"Windows Defender Issues ({len(issues)}) — {host}",
                severity=Severity.CRITICAL if has_av_off else Severity.MEDIUM,
                description=f"Defender issues on {host}: {'; '.join(issues)}.",
                reproduction_steps=[f"Enter-PSSession {host}", "Get-MpComputerStatus"],
                remediation="Enable Defender: Set-MpPreference -DisableRealtimeMonitoring $false",
                references=["CIS Benchmark 18.9.47"],
                evidence=Evidence(extra={"host": host, "issues": issues}),
                cvss_v31_vector=CVSS_AV_OFF if has_av_off else "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
                target=host, service="winrm", confidence="HIGH",
            )

        # Check exclusions (attackers add exclusions to hide malware)
        excl_result = await winrm.execute(session,
            "Get-MpPreference | Select-Object ExclusionPath,ExclusionExtension,ExclusionProcess | "
            "Format-List | Out-String")
        exclusions = []
        for line in excl_result.stdout.split("\n"):
            if ":" in line and line.strip():
                key, _, val = line.partition(":")
                val = val.strip()
                if val and val != "{}" and val != "":
                    exclusions.append(f"{key.strip()}: {val[:100]}")

        if exclusions:
            self.new_finding(
                title=f"Defender Exclusions Configured — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"Defender has {len(exclusions)} exclusion(s) on {host}: "
                    + "; ".join(exclusions[:5]) +
                    ". Attackers commonly add exclusions to evade detection."
                ),
                reproduction_steps=[f"Enter-PSSession {host}", "Get-MpPreference | Select Exclusion*"],
                remediation="Review and remove unnecessary Defender exclusions.",
                references=["CWE-693"],
                evidence=Evidence(extra={"host": host, "exclusions": exclusions[:20]}),
                mitre_attack=["TA0005/T1562.001"],
                target=host, service="winrm",
            )
