"""SNMP Config Audit — SNMP agent configuration security."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

OID_SNMP_ENABLE_AUTH_TRAPS = "1.3.6.1.2.1.11.30.0"  # snmpEnableAuthenTraps
OID_SNMP_IN_BAD_COMMUNITY = "1.3.6.1.2.1.11.4.0"   # snmpInBadCommunityNames

CVSS_V2_ENABLED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"


class SnmpConfigAudit(BaseModule):
    NAME        = "snmp_config_audit"
    DESCRIPTION = "SNMPv3 credentialed: agent config, v2c fallback, auth traps, access controls"
    PHASE       = 5
    TAGS        = ["credentialed", "snmp", "config", "hardening"]

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
            await self._audit_config(host, transport_mgr.snmpv3, session)

        return self._make_result(start)

    async def _audit_config(self, host: str, snmp, session) -> None:
        # Check if auth traps are enabled
        auth_traps = await snmp.snmp_get(session, OID_SNMP_ENABLE_AUTH_TRAPS)
        if auth_traps and auth_traps[0].value == "2":  # disabled(2)
            self.new_finding(
                title=f"SNMP Authentication Traps Disabled — {host}",
                severity=Severity.LOW,
                description="SNMP auth failure traps disabled. Failed auth attempts won't trigger alerts.",
                reproduction_steps=[f"snmpget -v3 {host} {OID_SNMP_ENABLE_AUTH_TRAPS}"],
                remediation="Enable auth traps in snmpd.conf: authtrapenable 1",
                references=["CWE-778"],
                evidence=Evidence(extra={"host": host}),
                target=host, service="snmp",
            )

        # Check bad community name counter (indicates v2c is still active)
        bad_comm = await snmp.snmp_get(session, OID_SNMP_IN_BAD_COMMUNITY)
        if bad_comm and bad_comm[0].value.isdigit() and int(bad_comm[0].value) > 0:
            self.new_finding(
                title=f"SNMPv2c Still Active (Bad Community Attempts: {bad_comm[0].value}) — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"SNMPv2c is still active on {host} — {bad_comm[0].value} failed community string "
                    "attempts detected. SNMPv2c transmits community strings in plaintext."
                ),
                reproduction_steps=[f"snmpget -v3 {host} {OID_SNMP_IN_BAD_COMMUNITY}"],
                remediation="Disable SNMPv2c. Use SNMPv3 with authPriv only.",
                references=["CWE-319"],
                evidence=Evidence(extra={"host": host, "bad_attempts": bad_comm[0].value}),
                cvss_v31_vector=CVSS_V2_ENABLED,
                target=host, service="snmp",
            )
