"""SNMP auditor — community string testing and information disclosure."""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_SNMP_PUBLIC = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_SNMP_PUBLIC = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_SNMP_WRITE  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS40_SNMP_WRITE = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
DEFAULT_COMMUNITIES = [
    "public", "private", "community", "manager",
    "snmpd", "admin", "password", "cisco", "secret",
    "test", "default", "read", "write", "monitor",
]


class SnmpAudit(BaseModule):
    """SNMP security auditor."""

    NAME        = "snmp_audit"
    DESCRIPTION = "Test SNMP for default community strings and information disclosure"
    PHASE       = 4
    TAGS        = ["services", "snmp", "community", "cwe-260"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        hosts = self.config.extra.get("live_hosts", [self.config.target])

        for host in hosts[:20]:
            if not self.check_scope(host):
                continue
            await self._audit_snmp(host)

        return self._make_result(start)

    async def _audit_snmp(self, host: str) -> None:
        """Test SNMP community strings via UDP probe."""
        await self.rate_limit()

        for community in DEFAULT_COMMUNITIES:
            success, data = await self._snmp_get(host, community)
            if success:
                is_private = community in ("private", "write", "manager")
                ev = Evidence(
                    extra={
                        "host":       host,
                        "community":  community,
                        "oid_data":   data[:200] if data else "",
                        "is_writable": is_private,
                    }
                )
                self.new_finding(
                    title=f"SNMP Default Community String '{community}' — {host}",
                    severity=Severity.HIGH if not is_private else Severity.CRITICAL,
                    description=(
                        f"SNMP community string '{community}' is valid on {host}. "
                        + ("This is a READ-WRITE community — full device configuration access!"
                           if is_private else
                           "Full system info disclosure: network config, routing tables, running processes.")
                    ),
                    reproduction_steps=[
                        f"snmpwalk -v2c -c {community} {host}",
                        f"snmpget -v2c -c {community} {host} 1.3.6.1.2.1.1.1.0",
                    ],
                    remediation=(
                        "Change default community strings to strong, unique values. "
                        "Restrict SNMP access by source IP (ACL). "
                        "Use SNMPv3 with authentication and encryption. "
                        "Disable SNMP if not required."
                    ),
                    references=["CWE-260", "CWE-200"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_SNMP_WRITE if is_private else CVSS_SNMP_PUBLIC,
                    cvss_v40_vector=CVSS40_SNMP_WRITE,
                    mitre_attack=["TA0007/T1602.001"],
                    target=host,
                    port=161,
                    service="snmp",
                )
                break  # One finding per host

    async def _snmp_get(self, host: str, community: str) -> tuple[bool, str]:
        """Send SNMP GET request for sysDescr OID."""
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, self._snmp_get_sync, host, community)
            return result
        except Exception:
            return False, ""

    def _snmp_get_sync(self, host: str, community: str) -> tuple[bool, str]:
        """Synchronous SNMP GET using pysnmp or raw UDP."""
        try:
            from pysnmp.hlapi import (
                getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
                ContextData, ObjectType, ObjectIdentity,
            )
            error_indication, error_status, _, varBinds = next(
                getCmd(
                    SnmpEngine(),
                    CommunityData(community, mpModel=1),
                    UdpTransportTarget((host, 161), timeout=2, retries=0),
                    ContextData(),
                    ObjectType(ObjectIdentity("1.3.6.1.2.1.1.1.0")),
                )
            )
            if not error_indication and not error_status:
                return True, str(varBinds[0]) if varBinds else ""
            return False, ""
        except ImportError:
            return self._snmp_raw(host, community)
        except Exception:
            return False, ""

    def _snmp_raw(self, host: str, community: str) -> tuple[bool, str]:
        """Raw UDP SNMP v2c GET probe."""
        import socket
        try:
            # Build minimal SNMP GET for sysDescr
            comm_bytes = community.encode()
            pdu = (
                b"\x30"  # SEQUENCE
                + bytes([len(comm_bytes) + 30])
                + b"\x02\x01\x01"  # version: SNMPv2c
                + b"\x04" + bytes([len(comm_bytes)]) + comm_bytes
                + b"\xa0\x19"  # GetRequest-PDU
                + b"\x02\x04\x00\x00\x00\x01"  # request-id
                + b"\x02\x01\x00"  # error-status
                + b"\x02\x01\x00"  # error-index
                + b"\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00"
            )
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2.0)
            sock.sendto(pdu, (host, 161))
            data, _ = sock.recvfrom(512)
            sock.close()
            return True, data.decode(errors="ignore")
        except Exception:
            return False, ""


class TestSnmpAudit:
    def test_default_communities(self) -> None:
        assert "public" in DEFAULT_COMMUNITIES
        assert "private" in DEFAULT_COMMUNITIES
        assert len(DEFAULT_COMMUNITIES) >= 10
