"""Windows Firewall Audit — profiles, rules, exceptions via WinRM."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_FW_OFF = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"


class WinFirewallAudit(BaseModule):
    NAME        = "win_firewall_audit"
    DESCRIPTION = "WinRM credentialed: Windows Firewall profiles, rules, exceptions"
    PHASE       = 5
    TAGS        = ["credentialed", "windows", "firewall", "hardening"]

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
            await self._audit_firewall(host, transport_mgr.winrm, session)

        return self._make_result(start)

    async def _audit_firewall(self, host: str, winrm, session) -> None:
        profile_result = await winrm.execute(session,
            "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction | "
            "Format-Table -AutoSize | Out-String")

        disabled_profiles = []
        allow_inbound = []
        for line in profile_result.stdout.split("\n"):
            parts = line.split()
            if len(parts) >= 3 and parts[0] in ("Domain", "Private", "Public"):
                if parts[1].lower() == "false":
                    disabled_profiles.append(parts[0])
                if len(parts) >= 3 and parts[2].lower() == "allow":
                    allow_inbound.append(parts[0])

        if disabled_profiles:
            self.new_finding(
                title=f"Windows Firewall Disabled — {', '.join(disabled_profiles)} — {host}",
                severity=Severity.HIGH,
                description=f"Firewall disabled for profiles: {', '.join(disabled_profiles)} on {host}.",
                reproduction_steps=[f"Enter-PSSession {host}", "Get-NetFirewallProfile"],
                remediation="Enable: Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True",
                references=["CIS Benchmark 9.1"],
                evidence=Evidence(extra={"host": host, "disabled": disabled_profiles}),
                cvss_v31_vector=CVSS_FW_OFF,
                target=host, service="winrm", confidence="HIGH",
            )

        if allow_inbound:
            self.new_finding(
                title=f"Firewall Default Inbound Allow — {', '.join(allow_inbound)} — {host}",
                severity=Severity.MEDIUM,
                description=f"Default inbound action is Allow for: {', '.join(allow_inbound)}.",
                reproduction_steps=[f"Enter-PSSession {host}", "Get-NetFirewallProfile | Select DefaultInboundAction"],
                remediation="Set-NetFirewallProfile -DefaultInboundAction Block",
                references=["CIS Benchmark 9.1"],
                evidence=Evidence(extra={"host": host, "allow_profiles": allow_inbound}),
                target=host, service="winrm",
            )

        # Count inbound allow rules
        rules_result = await winrm.execute(session,
            "(Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Measure-Object).Count")
        try:
            rule_count = int(rules_result.stdout.strip())
            if rule_count > 50:
                self.new_finding(
                    title=f"Excessive Inbound Firewall Rules ({rule_count}) — {host}",
                    severity=Severity.LOW,
                    description=f"{rule_count} inbound allow rules on {host}. Review for unnecessary entries.",
                    reproduction_steps=[f"Enter-PSSession {host}", "Get-NetFirewallRule -Direction Inbound -Action Allow"],
                    remediation="Audit and remove unnecessary firewall rules.",
                    references=["CWE-284"],
                    evidence=Evidence(extra={"host": host, "rule_count": rule_count}),
                    target=host, service="winrm",
                )
        except (ValueError, TypeError):
            pass
