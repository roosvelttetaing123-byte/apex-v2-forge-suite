"""Windows Registry Audit — security-relevant registry keys via WinRM."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_REG_HIGH = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS_REG_MED  = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N"

# Security registry checks: (path, value_name, bad_values, description, severity)
REGISTRY_CHECKS = [
    ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
     "EnableLUA", ["0"], "UAC disabled — all apps run elevated", Severity.CRITICAL),
    ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
     "ConsentPromptBehaviorAdmin", ["0"], "UAC prompt disabled for admins", Severity.HIGH),
    ("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest",
     "UseLogonCredential", ["1"], "WDigest caching cleartext passwords in memory", Severity.CRITICAL),
    ("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
     "RunAsPPL", ["0", ""], "LSA not running as Protected Process Light", Severity.HIGH),
    ("HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
     "EnableMulticast", ["1", ""], "LLMNR enabled — credential relay risk", Severity.HIGH),
    ("HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NetBT\\Parameters",
     "NodeType", ["1", ""], "NetBIOS over TCP not disabled — NBNS poisoning", Severity.MEDIUM),
    ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
     "LocalAccountTokenFilterPolicy", ["1"], "Remote UAC filtering disabled", Severity.HIGH),
    ("HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
     "LmCompatibilityLevel", ["0", "1", "2"], "NTLMv1 allowed — weak auth", Severity.HIGH),
    ("HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Winlogon",
     "DefaultPassword", ["*"], "AutoLogon password stored in registry", Severity.CRITICAL),
]


class WinRegistryAudit(BaseModule):
    NAME        = "win_registry_audit"
    DESCRIPTION = "WinRM credentialed: UAC, WDigest, LSA, LLMNR, NetBIOS, AutoLogon registry keys"
    PHASE       = 5
    TAGS        = ["credentialed", "windows", "registry", "hardening", "cwe-522"]

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
            await self._audit_registry(host, transport_mgr.winrm, session)

        return self._make_result(start)

    async def _audit_registry(self, host: str, winrm, session) -> None:
        failures = []
        for reg_path, value_name, bad_values, desc, severity in REGISTRY_CHECKS:
            result = await winrm.execute(session,
                f"try {{ (Get-ItemProperty -Path '{reg_path}' -Name '{value_name}' "
                f"-ErrorAction Stop).{value_name} }} catch {{ 'NOT_FOUND' }}")

            actual = result.stdout.strip()
            if actual == "NOT_FOUND":
                # Some checks trigger on missing values
                if "" in bad_values:
                    failures.append({"key": f"{reg_path}\\{value_name}",
                                    "value": "NOT SET", "desc": desc, "severity": severity})
                continue

            if "*" in bad_values and actual:
                # Any value is bad (e.g., AutoLogon password)
                failures.append({"key": f"{reg_path}\\{value_name}",
                                "value": "***REDACTED***", "desc": desc, "severity": severity})
            elif actual in bad_values:
                failures.append({"key": f"{reg_path}\\{value_name}",
                                "value": actual, "desc": desc, "severity": severity})

        if failures:
            critical = [f for f in failures if f["severity"] == Severity.CRITICAL]
            worst = Severity.CRITICAL if critical else Severity.HIGH

            self.new_finding(
                title=f"Registry Security Misconfigurations ({len(failures)}) — {host}",
                severity=worst,
                description=(
                    f"{len(failures)} security-relevant registry issues on {host}: " +
                    "; ".join(f"{f['desc']} ({f['key']}={f['value']})" for f in failures[:5])
                ),
                reproduction_steps=[f"Enter-PSSession {host}", "Get-ItemProperty -Path <key>"],
                remediation="Apply CIS registry hardening. Use GPO for domain-wide enforcement.",
                references=["CWE-522", "CIS Benchmark 2.3, 18.x"],
                evidence=Evidence(extra={"host": host, "failures": failures}),
                cvss_v31_vector=CVSS_REG_HIGH,
                mitre_attack=["TA0006/T1003.001"],
                target=host, service="winrm",
            )
