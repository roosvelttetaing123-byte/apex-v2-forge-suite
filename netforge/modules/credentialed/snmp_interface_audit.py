"""SNMP Interface Audit — network interface, routing, ARP via SNMPv3."""
from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

OID_IF_TABLE     = "1.3.6.1.2.1.2.2"         # ifTable
OID_IF_DESCR     = "1.3.6.1.2.1.2.2.1.2"     # ifDescr
OID_IF_STATUS    = "1.3.6.1.2.1.2.2.1.8"     # ifOperStatus
OID_IP_ADDR      = "1.3.6.1.2.1.4.20"        # ipAddrTable
OID_IP_ROUTE     = "1.3.6.1.2.1.4.21"        # ipRouteTable
OID_ARP          = "1.3.6.1.2.1.4.22"        # ipNetToMediaTable


class SnmpInterfaceAudit(BaseModule):
    NAME        = "snmp_interface_audit"
    DESCRIPTION = "SNMPv3 credentialed: network interfaces, IP config, routing tables, ARP"
    PHASE       = 5
    TAGS        = ["credentialed", "snmp", "network", "interfaces", "routing"]

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
            await self._audit_interfaces(host, transport_mgr.snmpv3, session)

        return self._make_result(start)

    async def _audit_interfaces(self, host: str, snmp, session) -> None:
        # Walk interfaces
        interfaces = await snmp.snmp_walk(session, OID_IF_DESCR, max_results=100)
        ip_addrs = await snmp.snmp_walk(session, OID_IP_ADDR, max_results=100)
        routes = await snmp.snmp_walk(session, OID_IP_ROUTE, max_results=200)

        iface_count = len(interfaces)
        ip_count = len(ip_addrs)
        route_count = len(routes)

        # Flag multi-homed hosts (potential pivot points)
        unique_ips = set()
        for ip_entry in ip_addrs:
            ip_val = ip_entry.value
            if ip_val and ip_val not in ("0.0.0.0", "127.0.0.1"):
                unique_ips.add(ip_val)

        if len(unique_ips) > 2:
            self.new_finding(
                title=f"Multi-Homed Host ({len(unique_ips)} IPs) — Pivot Risk — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"Host {host} has {len(unique_ips)} IP addresses across {iface_count} interfaces: "
                    f"{', '.join(list(unique_ips)[:10])}. Multi-homed hosts are pivot points."
                ),
                reproduction_steps=[f"snmpwalk -v3 -u <user> -l authPriv {host} {OID_IP_ADDR}"],
                remediation="Review network segmentation. Restrict routing between interfaces.",
                references=["CWE-284"],
                evidence=Evidence(extra={
                    "host": host, "interfaces": iface_count,
                    "ips": list(unique_ips)[:20], "routes": route_count,
                }),
                mitre_attack=["TA0008/T1021"],
                target=host, service="snmp",
            )

        # Flag default routes
        default_routes = [r for r in routes if "0.0.0.0" in r.value or r.oid.endswith(".0.0.0.0")]
        if len(default_routes) > 1:
            self.new_finding(
                title=f"Multiple Default Routes — {host}",
                severity=Severity.LOW,
                description=f"Host {host} has {len(default_routes)} default routes — asymmetric routing risk.",
                reproduction_steps=[f"snmpwalk -v3 {host} {OID_IP_ROUTE}"],
                remediation="Review routing table. Remove unnecessary default routes.",
                references=["CWE-284"],
                evidence=Evidence(extra={"host": host, "default_routes": len(default_routes)}),
                target=host, service="snmp",
            )
