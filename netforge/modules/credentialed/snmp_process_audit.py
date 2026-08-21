"""SNMP Process Audit — running processes via HOST-RESOURCES-MIB."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

OID_HR_SW_RUN_NAME = "1.3.6.1.2.1.25.4.2.1.2"   # hrSWRunName
OID_HR_SW_RUN_PATH = "1.3.6.1.2.1.25.4.2.1.4"   # hrSWRunPath
OID_HR_SW_RUN_PARAMS = "1.3.6.1.2.1.25.4.2.1.5"  # hrSWRunParameters

DANGEROUS_PROCESSES = {
    "telnetd", "rshd", "rlogind", "tftpd", "fingerd",
    "vsftpd", "proftpd", "pure-ftpd",  # FTP daemons
    "nc", "ncat", "socat",              # Reverse shell indicators
    "meterpreter", "beacon",            # Implants
    "cryptominer", "xmrig", "ccminer", "minerd",  # Cryptominers
    "tor", "proxychains",               # Anonymization
}


class SnmpProcessAudit(BaseModule):
    NAME        = "snmp_process_audit"
    DESCRIPTION = "SNMPv3 credentialed: running process enumeration, dangerous service detection"
    PHASE       = 5
    TAGS        = ["credentialed", "snmp", "processes", "services"]

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
            await self._audit_processes(host, transport_mgr.snmpv3, session)

        return self._make_result(start)

    async def _audit_processes(self, host: str, snmp, session) -> None:
        processes = await snmp.snmp_walk(session, OID_HR_SW_RUN_NAME, max_results=300)

        proc_names = [p.value.lower() for p in processes]
        found_dangerous = [p for p in proc_names if p in DANGEROUS_PROCESSES]

        if found_dangerous:
            self.new_finding(
                title=f"Dangerous Processes Running — {host}",
                severity=Severity.HIGH,
                description=(
                    f"Found {len(found_dangerous)} dangerous/suspicious processes on {host} via SNMP: "
                    f"{', '.join(set(found_dangerous))}."
                ),
                reproduction_steps=[f"snmpwalk -v3 {host} {OID_HR_SW_RUN_NAME}"],
                remediation="Investigate and stop unauthorized processes.",
                references=["CWE-272"],
                evidence=Evidence(extra={"host": host, "processes": list(set(found_dangerous))}),
                mitre_attack=["TA0007/T1057"],
                target=host, service="snmp", confidence="HIGH",
            )

        # Store process list for enrichment
        self.config.extra.setdefault("snmp_processes", {})[host] = proc_names
