"""SNMP Software Audit — installed software inventory via HOST-RESOURCES-MIB."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

OID_HR_SW_INSTALLED = "1.3.6.1.2.1.25.6.3.1.2"  # hrSWInstalledName


class SnmpSoftwareAudit(BaseModule):
    NAME        = "snmp_software_audit"
    DESCRIPTION = "SNMPv3 credentialed: installed software inventory via HOST-RESOURCES-MIB"
    PHASE       = 5
    TAGS        = ["credentialed", "snmp", "software", "inventory"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        transport_mgr = self.config.extra.get("transport_manager")
        if not transport_mgr or not transport_mgr.has_creds("snmpv3"):
            return self._make_result(start, skipped=True, skip_reason="no SNMPv3 credentials")

        hosts = self.config.extra.get("live_hosts", [self.config.target])
        for host in hosts[:20]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            session = await transport_mgr.get_snmpv3_session(host)
            if not session:
                continue
            await self._audit_software(host, transport_mgr.snmpv3, session)

        return self._make_result(start)

    async def _audit_software(self, host: str, snmp, session) -> None:
        software = await snmp.snmp_walk(session, OID_HR_SW_INSTALLED, max_results=500)

        sw_names = [s.value for s in software]

        # Flag known vulnerable/EOL software
        eol_patterns = ["windows xp", "windows 7", "windows 2003", "windows 2008",
                       "ubuntu 14.04", "ubuntu 16.04", "centos 6", "debian 8", "debian 9"]
        found_eol = [s for s in sw_names if any(p in s.lower() for p in eol_patterns)]

        if found_eol:
            self.new_finding(
                title=f"End-of-Life Software Detected — {host}",
                severity=Severity.HIGH,
                description=f"EOL software on {host}: {', '.join(found_eol[:5])}. No security patches.",
                reproduction_steps=[f"snmpwalk -v3 {host} {OID_HR_SW_INSTALLED}"],
                remediation="Upgrade to supported versions.",
                references=["CWE-1104"],
                evidence=Evidence(extra={"host": host, "eol_software": found_eol[:20]}),
                target=host, service="snmp", confidence="HIGH",
            )

        self.config.extra.setdefault("snmp_software", {})[host] = sw_names
