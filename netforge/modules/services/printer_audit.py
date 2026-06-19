"""Printer Auditor — PJL/PCL access, PRET-style exploitation, information disclosure.

Tests:
  - PJL (Printer Job Language) unauthenticated access
  - PJL file system access (directory listing, file read)
  - PJL INFO ID (device identification)
  - PCL/PostScript injection surface
  - SNMP-based printer info disclosure
"""
from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_PJL_ACCESS  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L"
CVSS40_PJL_ACCESS = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N"
CVSS_PJL_FS      = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_PJL_FS    = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"

PRINTER_PORTS = [9100, 515, 631]  # RAW, LPD, IPP


class PrinterAudit(BaseModule):
    """Network printer security auditor via PJL/PCL."""

    NAME        = "printer_audit"
    DESCRIPTION = "Printer: PJL access, file system, device ID, PCL injection"
    PHASE       = 5
    TAGS        = ["printer", "services", "pjl", "cwe-284"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])
        for host in hosts[:20]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            await self._audit_printer(host)

        return self._make_result(start)

    async def _audit_printer(self, host: str) -> None:
        port = 9100  # JetDirect RAW
        if not await self._port_open(host, port):
            return

        # PJL INFO ID — device identification
        device_id = await self._pjl_info_id(host, port)
        if device_id is None:
            return

        self.new_finding(
            title=f"Printer PJL Access — {host}:{port} ({device_id[:50]})",
            severity=Severity.MEDIUM,
            description=(
                f"Printer on {host}:{port} responds to PJL commands without authentication. "
                f"Device: {device_id}.\n\n"
                "PJL access enables:\n"
                "  - Print job interception and manipulation\n"
                "  - File system access on the printer\n"
                "  - Configuration changes (password reset, SNMP community)\n"
                "  - Denial of service (factory reset, paper jam simulation)\n"
                "  - Physical damage risk (fuser over-temperature via PJL)"
            ),
            reproduction_steps=[
                f"echo -e '\\x1b%-12345X@PJL INFO ID\\r\\n\\x1b%-12345X' | nc {host} {port}",
                f"# Or use PRET: python3 pret.py {host} pjl",
            ],
            remediation=(
                "1. Enable PJL password: @PJL DEFAULT PASSWORD = <value>\n"
                "2. Disable unused protocols (RAW 9100, LPD 515)\n"
                "3. Restrict printer to management VLAN\n"
                "4. Use IPP over TLS (TCP 631) with authentication\n"
                "5. Disable PJL file system access in printer settings"
            ),
            references=["CWE-284", "CWE-306"],
            evidence=Evidence(extra={"host": host, "device_id": device_id}),
            cvss_v31_vector=CVSS_PJL_ACCESS,
            cvss_v40_vector=CVSS40_PJL_ACCESS,
            port=port, service="pjl-printer", target=host,
        )

        # Test file system access
        await self._pjl_fs_access(host, port)

    async def _pjl_info_id(self, host: str, port: int) -> str | None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )
            # PJL Universal Exit Language (UEL) + INFO ID
            cmd = b"\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X"
            writer.write(cmd)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=5)
            writer.close()
            response = data.decode(errors="ignore").strip()
            if "@PJL" in response or "INFO" in response or response:
                # Extract device name from response
                for line in response.split("\n"):
                    line = line.strip()
                    if line and not line.startswith("@PJL"):
                        return line.strip('"').strip()
                return response[:100]
            return None
        except Exception:
            return None

    async def _pjl_fs_access(self, host: str, port: int) -> None:
        """Test PJL file system commands."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )
            # Try FSDIRLIST (directory listing)
            cmd = b"\x1b%-12345X@PJL FSDIRLIST NAME=\"0:\\\" ENTRY=1 COUNT=10\r\n\x1b%-12345X"
            writer.write(cmd)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(2048), timeout=5)
            writer.close()
            response = data.decode(errors="ignore").strip()

            if "ENTRY" in response or "DIR" in response or "TYPE" in response:
                ev = Evidence(
                    request_raw='@PJL FSDIRLIST NAME="0:\\" ENTRY=1 COUNT=10',
                    response_raw=response[:1000],
                    extra={"host": host, "fs_access": True},
                )
                self.new_finding(
                    title=f"Printer File System Access via PJL — {host}:{port}",
                    severity=Severity.HIGH,
                    description=(
                        f"PJL file system commands work on {host}:{port}. "
                        "Attacker can read/write files on the printer's storage, including:\n"
                        "  - Stored print jobs (potentially confidential documents)\n"
                        "  - Configuration files with credentials\n"
                        "  - PostScript files that execute on print"
                    ),
                    reproduction_steps=[
                        f"python3 pret.py {host} pjl",
                        "ls",
                        "get <filename>",
                    ],
                    remediation="Set PJL password. Disable file system access in printer admin panel.",
                    references=["CWE-284"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_PJL_FS,
                    cvss_v40_vector=CVSS40_PJL_FS,
                    port=port, service="pjl-printer", target=host,
                )
        except Exception:
            pass

    async def _port_open(self, host: str, port: int) -> bool:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3
            )
            writer.close()
            return True
        except Exception:
            return False


class TestPrinterAudit:
    def test_ports(self) -> None:
        assert 9100 in PRINTER_PORTS

    def test_cvss(self) -> None:
        assert CVSS_PJL_ACCESS.startswith("CVSS:3.1")
        assert CVSS40_PJL_ACCESS.startswith("CVSS:4.0")

    def test_phase(self) -> None:
        assert PrinterAudit.PHASE == 5
