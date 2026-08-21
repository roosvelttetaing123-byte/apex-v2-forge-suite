"""SNMP System Info — credentialed SNMPv3 full system inventory.

Walks:
  - sysDescr, sysName, sysLocation, sysContact, sysUpTime
  - hrSystemUptime, hrSystemDate
  - OS identification and version extraction
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

# Standard MIB OIDs
OID_SYSDESCR    = "1.3.6.1.2.1.1.1.0"
OID_SYSNAME     = "1.3.6.1.2.1.1.5.0"
OID_SYSLOCATION = "1.3.6.1.2.1.1.6.0"
OID_SYSCONTACT  = "1.3.6.1.2.1.1.4.0"
OID_SYSUPTIME   = "1.3.6.1.2.1.1.3.0"
OID_SYSOBJECTID = "1.3.6.1.2.1.1.2.0"


class SnmpSystemInfo(BaseModule):
    NAME        = "snmp_system_info"
    DESCRIPTION = "SNMPv3 credentialed: full system inventory — OS, hardware, uptime, contact"
    PHASE       = 5
    TAGS        = ["credentialed", "snmp", "inventory", "compliance"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        transport_mgr = self.config.extra.get("transport_manager")
        if not transport_mgr or not transport_mgr.has_creds("snmpv3"):
            return self._make_result(start, skipped=True, skip_reason="no SNMPv3 credentials")

        hosts = self.config.extra.get("live_hosts", [self.config.target])
        for host in hosts[:30]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            session = await transport_mgr.get_snmpv3_session(host)
            if not session:
                continue
            await self._collect_sysinfo(host, transport_mgr.snmpv3, session)

        return self._make_result(start)

    async def _collect_sysinfo(self, host: str, snmp, session) -> None:
        sys_descr = await snmp.snmp_get(session, OID_SYSDESCR)
        sys_name = await snmp.snmp_get(session, OID_SYSNAME)
        sys_location = await snmp.snmp_get(session, OID_SYSLOCATION)
        sys_contact = await snmp.snmp_get(session, OID_SYSCONTACT)
        sys_uptime = await snmp.snmp_get(session, OID_SYSUPTIME)

        descr = sys_descr[0].value if sys_descr else "unknown"
        name = sys_name[0].value if sys_name else "unknown"
        location = sys_location[0].value if sys_location else ""
        contact = sys_contact[0].value if sys_contact else ""
        uptime = sys_uptime[0].value if sys_uptime else ""

        # Flag missing contact/location (compliance gap)
        issues = []
        if not location or location in ("", "Unknown", "not set"):
            issues.append("sysLocation not configured")
        if not contact or contact in ("", "Unknown", "not set"):
            issues.append("sysContact not configured")

        # Flag extreme uptime (no reboots = no kernel patches)
        if uptime:
            try:
                ticks = int(uptime)
                days = ticks / 8640000  # centiseconds to days
                if days > 365:
                    issues.append(f"Uptime {int(days)} days — likely unpatched")
            except (ValueError, TypeError):
                pass

        if issues:
            self.new_finding(
                title=f"SNMP System Configuration Issues — {host}",
                severity=Severity.LOW,
                description=(
                    f"SNMP system info for {host} ({name}): {'; '.join(issues)}. "
                    f"System: {descr[:200]}"
                ),
                reproduction_steps=[f"snmpget -v3 -u <user> -l authPriv {host} {OID_SYSDESCR}"],
                remediation="Configure sysLocation and sysContact. Schedule regular patching/reboots.",
                references=["CWE-1059"],
                evidence=Evidence(extra={
                    "host": host, "sysDescr": descr[:500], "sysName": name,
                    "sysLocation": location, "sysContact": contact, "sysUptime": uptime,
                }),
                target=host, service="snmp",
            )

        # Store for other SNMP modules
        self.config.extra.setdefault("snmp_sysinfo", {})[host] = {
            "descr": descr, "name": name, "location": location,
            "contact": contact, "uptime": uptime,
        }
