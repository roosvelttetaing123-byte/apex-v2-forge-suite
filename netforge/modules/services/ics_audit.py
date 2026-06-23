"""ICS/SCADA Auditor — Modbus/DNP3 unauthenticated access, S7comm detection.

Tests:
  - Modbus TCP unauthenticated access (coil/register read)
  - DNP3 service detection
  - Siemens S7comm detection
  - BACnet device discovery
  - EtherNet/IP service identification
"""
from __future__ import annotations

import asyncio
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_MODBUS     = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H"
CVSS40_MODBUS   = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:H/SC:L/SI:H/SA:H"
CVSS_S7COMM     = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:H/A:H"
CVSS40_S7COMM   = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:H/VA:H/SC:L/SI:H/SA:H"
CVSS_DETECT     = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
CVSS40_DETECT   = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"

ICS_PORTS = {
    502: "Modbus TCP",
    20000: "DNP3",
    102: "S7comm (Siemens)",
    47808: "BACnet",
    44818: "EtherNet/IP",
    2222: "EtherNet/IP (alt)",
}


class IcsAudit(BaseModule):
    """ICS/SCADA protocol security auditor."""

    NAME        = "ics_audit"
    DESCRIPTION = "ICS: Modbus unauthenticated, DNP3, S7comm, BACnet, EtherNet/IP"
    PHASE       = 4
    TAGS        = ["ics", "scada", "ot", "modbus", "cwe-306"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])
        for host in hosts[:10]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            await self._audit_ics(host)

        return self._make_result(start)

    async def _audit_ics(self, host: str) -> None:
        await self._check_modbus(host)
        await self._check_s7comm(host)
        await self._check_dnp3(host)
        await self._check_bacnet(host)
        await self._check_enip(host)

    async def _check_modbus(self, host: str) -> None:
        """Test Modbus TCP access — read coils and holding registers."""
        port = 502
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )

            # Modbus TCP: Read Device Identification (function 0x2B, MEI 0x0E)
            # MBAP header: transaction_id(2) + protocol_id(2) + length(2) + unit_id(1)
            # PDU: function_code(1) + mei_type(1) + read_device_id(1) + object_id(1)
            mbap = struct.pack(">HHHB", 0x0001, 0x0000, 0x0005, 0x01)
            pdu = struct.pack(">BBBB", 0x2B, 0x0E, 0x01, 0x00)
            writer.write(mbap + pdu)
            await writer.drain()

            data = await asyncio.wait_for(reader.read(256), timeout=5)

            device_info = ""
            if len(data) > 9 and data[7] == 0x2B:
                # Parse device identification response
                try:
                    obj_data = data[15:]
                    if obj_data:
                        device_info = obj_data.decode(errors="ignore")[:100]
                except Exception:
                    pass

            # Try reading holding registers (function 0x03)
            mbap2 = struct.pack(">HHHB", 0x0002, 0x0000, 0x0006, 0x01)
            pdu2 = struct.pack(">BHH", 0x03, 0x0000, 0x000A)  # Read 10 registers at addr 0
            writer.write(mbap2 + pdu2)
            await writer.drain()
            data2 = await asyncio.wait_for(reader.read(256), timeout=5)

            registers_read = False
            register_values = []
            if len(data2) > 9 and data2[7] == 0x03:
                registers_read = True
                byte_count = data2[8]
                for i in range(0, byte_count, 2):
                    if i + 1 < byte_count:
                        val = struct.unpack(">H", data2[9 + i:11 + i])[0]
                        register_values.append(val)

            writer.close()

            # Only report if we got a valid Modbus protocol response, not just a TCP connection
            modbus_confirmed = (
                (len(data) > 9 and data[7] == 0x2B) or registers_read
            )
            if not modbus_confirmed:
                self.log.debug("TCP 502 connected on %s but no Modbus protocol response", host)
                return

            ev = Evidence(
                request_raw=f"Modbus TCP Read Holding Registers → {host}:502",
                extra={
                    "host": host, "device_info": device_info,
                    "registers_read": registers_read,
                    "register_values": register_values[:10],
                },
            )

            self.new_finding(
                title=f"Modbus TCP Unauthenticated Access — {host}:502",
                severity=Severity.CRITICAL,
                description=(
                    f"Modbus TCP on {host}:502 accepts unauthenticated commands. "
                    f"Device: {device_info or 'unknown'}.\n"
                    + (f"Holding registers (first 10): {register_values[:10]}\n" if register_values else "")
                    + "\nModbus has NO built-in authentication. An attacker can:\n"
                    "  1. Read all process values (sensor data, setpoints)\n"
                    "  2. Write coils/registers (CONTROL PHYSICAL PROCESSES)\n"
                    "  3. Stop/start equipment, change setpoints\n"
                    "  4. Cause physical damage to industrial equipment\n\n"
                    "⚠ THIS IS AN OPERATIONAL TECHNOLOGY SYSTEM — MANIPULATION CAN CAUSE "
                    "PHYSICAL HARM TO PEOPLE AND EQUIPMENT ⚠"
                ),
                reproduction_steps=[
                    f"# Read holding registers:",
                    f"modbus read -a {host} -t 3 -s 0 -c 10",
                    f"# Or nmap: nmap -p 502 --script modbus-discover {host}",
                    f"# CAUTION: DO NOT write to ICS systems without explicit authorization",
                ],
                remediation=(
                    "1. NEVER expose Modbus TCP to corporate or internet networks\n"
                    "2. Segment OT networks from IT networks (Purdue Model Level 3)\n"
                    "3. Deploy industrial firewall/IDS (e.g., Claroty, Nozomi)\n"
                    "4. Implement Modbus/TCP security extensions if available\n"
                    "5. Monitor for anomalous Modbus commands"
                ),
                references=["CWE-306", "ICS-CERT", "MITRE ICS T0831"],
                evidence=ev,
                cvss_v31_vector=CVSS_MODBUS,
                cvss_v40_vector=CVSS40_MODBUS,
                port=port, service="modbus", target=host,
            )
        except Exception:
            pass

    async def _check_s7comm(self, host: str) -> None:
        """Detect Siemens S7 PLC via S7comm protocol on TCP 102."""
        port = 102
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )

            # COTP Connection Request (CR)
            cotp_cr = bytes([
                0x03, 0x00, 0x00, 0x16,  # TPKT header
                0x11,                      # COTP length
                0xe0,                      # CR type
                0x00, 0x00,                # dst ref
                0x00, 0x01,                # src ref
                0x00,                      # class
                0xc0, 0x01, 0x0a,          # src TSAP
                0xc1, 0x02, 0x01, 0x00,    # dst TSAP
                0xc2, 0x02, 0x01, 0x02,    # TPDU size
            ])

            writer.write(cotp_cr)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(256), timeout=5)
            writer.close()

            # Check for COTP Connection Confirm (CC = 0xd0)
            if len(data) > 5 and data[5] == 0xd0:
                ev = Evidence(
                    request_raw=f"S7comm COTP CR → {host}:102",
                    response_raw=f"COTP CC received ({len(data)} bytes)",
                    extra={"host": host, "s7comm_detected": True},
                )
                self.new_finding(
                    title=f"Siemens S7 PLC Detected — {host}:102 (S7comm)",
                    severity=Severity.HIGH,
                    description=(
                        f"Siemens S7 communication protocol detected on {host}:102. "
                        "S7comm allows reading/writing PLC memory, starting/stopping the CPU, "
                        "and downloading/uploading PLC programs — all without authentication in "
                        "older firmware versions.\n\n"
                        "THIS IS AN INDUSTRIAL CONTROL SYSTEM."
                    ),
                    reproduction_steps=[
                        f"nmap -p 102 --script s7-info {host}",
                        f"# Metasploit: use auxiliary/scanner/scada/siemens_s7_info",
                    ],
                    remediation=(
                        "1. Segment S7 PLCs on isolated OT network\n"
                        "2. Enable S7 CPU access protection (password)\n"
                        "3. Update firmware for TLS support\n"
                        "4. Deploy industrial firewall (Siemens SCALANCE S)"
                    ),
                    references=["CWE-306", "ICS-CERT"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_S7COMM,
                    cvss_v40_vector=CVSS40_S7COMM,
                    port=port, service="s7comm", target=host,
                )
        except Exception:
            pass

    @staticmethod
    def _dnp3_crc(data: bytes) -> int:
        """CRC-16 for DNP3 (polynomial 0x3D65, reflected)."""
        crc = 0x0000
        for byte in data:
            crc ^= byte
            for _ in range(8):
                if crc & 0x0001:
                    crc = (crc >> 1) ^ 0xA6BC
                else:
                    crc >>= 1
        return (~crc) & 0xFFFF

    async def _check_dnp3(self, host: str) -> None:
        """Detect DNP3 service on TCP 20000."""
        port = 20000
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )
            # DNP3 data link layer frame with correct CRC-16
            header = bytes([
                0x05, 0x64,  # Start bytes
                0x05,        # Length (5 bytes after this field)
                0xc0,        # Control (DIR, PRM, FCB, RESET_LINK)
                0x01, 0x00,  # Destination address (1)
                0x00, 0x00,  # Source address (0)
            ])
            crc_val = self._dnp3_crc(header)
            dnp3_probe = header + struct.pack("<H", crc_val)
            writer.write(dnp3_probe)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(256), timeout=5)
            writer.close()

            if len(data) >= 2 and data[0] == 0x05 and data[1] == 0x64:
                ev = Evidence(
                    request_raw=f"DNP3 link layer probe → {host}:20000",
                    extra={"host": host, "dnp3_detected": True},
                )
                self.new_finding(
                    title=f"DNP3 Protocol Detected — {host}:20000",
                    severity=Severity.HIGH,
                    description=(
                        f"DNP3 (Distributed Network Protocol) on {host}:20000. "
                        "DNP3 is used in SCADA/utility systems. "
                        "Without DNP3-SA (Secure Authentication), all commands are unauthenticated."
                    ),
                    reproduction_steps=[
                        f"nmap -p 20000 --script dnp3-info {host}",
                    ],
                    remediation="Enable DNP3 Secure Authentication (SA). Segment OT network.",
                    references=["CWE-306", "ICS-CERT"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_DETECT,
                    cvss_v40_vector=CVSS40_DETECT,
                    port=port, service="dnp3", target=host,
                )
        except Exception:
            pass

    async def _check_bacnet(self, host: str) -> None:
        """BACnet/IP device discovery via UDP broadcast on port 47808."""
        port = 47808
        # BACnet Who-Is request (BVLC + NPDU + APDU)
        who_is = bytes([
            0x81, 0x0b,        # BVLC type: Original-Broadcast-NPDU
            0x00, 0x08,        # BVLC length
            0x01, 0x20,        # NPDU: version 1, expecting reply
            0xff, 0xff,        # Destination network (broadcast)
            0x00,              # Destination MAC length (0 = broadcast)
            0x10,              # Hop count
            0x10, 0x08,        # APDU: Unconfirmed-Request, Who-Is service
        ])
        try:
            loop = asyncio.get_event_loop()
            transport, _ = await loop.create_datagram_endpoint(
                asyncio.DatagramProtocol,
                remote_addr=(host, port),
                family=10,  # AF_INET6 fallback; use AF_INET
            )
            transport.close()
        except Exception:
            pass

        try:
            import socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3)
            sock.sendto(who_is, (host, port))
            try:
                data, _ = sock.recvfrom(512)
                sock.close()
                # I-Am response starts with 0x81 (BVLC) and APDU service 0x10 0x00 (I-Am)
                if len(data) >= 4 and data[0] == 0x81:
                    ev = Evidence(
                        request_raw=f"BACnet Who-Is UDP → {host}:{port}",
                        extra={"host": host, "response_bytes": list(data[:16])},
                    )
                    self.new_finding(
                        title=f"BACnet Device Exposed — {host}:{port}",
                        severity=Severity.HIGH,
                        description=(
                            f"BACnet/IP device responded to Who-Is broadcast on {host}:{port}. "
                            "BACnet is used in building automation and SCADA. "
                            "Unauthenticated access allows reading/writing object properties "
                            "(temperature setpoints, HVAC control, alarm systems)."
                        ),
                        reproduction_steps=[
                            f"nmap -sU -p 47808 --script bacnet-info {host}",
                            "# Python: bacpypes or scapy BACnet layer",
                        ],
                        remediation=(
                            "Segment BACnet network from corporate/internet. "
                            "Enable BACnet/SC (secure connect) where supported. "
                            "Deploy industrial firewall to restrict Who-Is broadcasts."
                        ),
                        references=["CWE-306", "ASHRAE 135", "ICS-CERT"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_DETECT,
                        cvss_v40_vector=CVSS40_DETECT,
                        port=port, service="bacnet", target=host,
                    )
            except socket.timeout:
                sock.close()
        except Exception:
            pass

    async def _check_enip(self, host: str) -> None:
        """EtherNet/IP List Identity request on TCP 44818."""
        port = 44818
        # EtherNet/IP encapsulation: List Identity command (0x0063)
        list_identity = bytes([
            0x63, 0x00,  # Command: List Identity
            0x00, 0x00,  # Length: 0
            0x00, 0x00, 0x00, 0x00,  # Session handle
            0x00, 0x00, 0x00, 0x00,  # Status
            0x00, 0x00, 0x00, 0x00,  # Sender context (8 bytes)
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,  # Options
        ])
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )
            writer.write(list_identity)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(512), timeout=5)
            writer.close()

            # EtherNet/IP response starts with command echo 0x63 0x00
            if len(data) >= 4 and data[0] == 0x63 and data[1] == 0x00:
                # Try to extract product name from identity response
                product_name = ""
                try:
                    # Identity object: after fixed header, find ASCII product name
                    name_bytes = data[30:60]
                    product_name = name_bytes.decode(errors="ignore").strip("\x00")
                except Exception:
                    pass

                ev = Evidence(
                    request_raw=f"EtherNet/IP List Identity → {host}:{port}",
                    extra={"host": host, "product_name": product_name, "response_bytes": list(data[:16])},
                )
                self.new_finding(
                    title=f"EtherNet/IP PLC Exposed — {host}:{port}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"EtherNet/IP device responded to List Identity on {host}:{port}. "
                        f"Product: {product_name or 'unknown'}. "
                        "EtherNet/IP (CIP) is used for Allen-Bradley, Rockwell, and Omron PLCs. "
                        "Unauthenticated CIP access allows reading/writing I/O and program tags, "
                        "stopping CPU execution, and uploading/downloading PLC programs."
                    ),
                    reproduction_steps=[
                        f"nmap -p 44818 --script enip-info {host}",
                        "# CIP exploit: plcscan, CPPPO, EIPScanner",
                        f"python3 -c \"import cpppo; ...\" {host}",
                    ],
                    remediation=(
                        "Isolate PLCs in dedicated OT VLAN behind industrial DMZ. "
                        "Enable CIP security (CIP Security profile, TLS 1.2+). "
                        "Disable remote programming access from untrusted networks. "
                        "Deploy Rockwell Automation Security Wizard configuration."
                    ),
                    references=["CWE-306", "ODVA EtherNet/IP Spec", "ICS-CERT Advisory"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_MODBUS,
                    cvss_v40_vector=CVSS40_MODBUS,
                    port=port, service="enip", target=host,
                )
        except Exception:
            pass


class TestIcsAudit:
    def test_ports(self) -> None:
        assert 502 in ICS_PORTS
        assert 102 in ICS_PORTS

    def test_cvss(self) -> None:
        assert CVSS_MODBUS.startswith("CVSS:3.1")
        assert "/S:C/" in CVSS_MODBUS  # Changed scope for ICS

    def test_phase(self) -> None:
        assert IcsAudit.PHASE == 4
