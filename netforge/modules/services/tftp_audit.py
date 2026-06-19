"""TFTP Auditor — unauthenticated file access, directory traversal.

Tests:
  - Unauthenticated file read (no auth in TFTP protocol)
  - Common sensitive file retrieval
  - Directory traversal
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

CVSS_NOAUTH     = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_NOAUTH   = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_TRAVERSAL  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_TRAVERSAL = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"

# Files commonly found on TFTP (network device configs, boot files)
PROBE_FILES = [
    "running-config",
    "startup-config",
    "router-config",
    "switch-config",
    "default.cfg",
    "config.txt",
    "pxelinux.0",
    "pxelinux.cfg/default",
    "/etc/passwd",
    "../../../etc/passwd",
]


class TftpAudit(BaseModule):
    """TFTP unauthenticated file access auditor."""

    NAME        = "tftp_audit"
    DESCRIPTION = "TFTP: unauthenticated file read, directory traversal, config exposure"
    PHASE       = 5
    TAGS        = ["tftp", "services", "file-share", "cwe-306"]

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
            await self._audit_tftp(host)

        return self._make_result(start)

    async def _audit_tftp(self, host: str) -> None:
        port = 69
        files_found = []

        for filename in PROBE_FILES:
            await self.rate_limit()
            content = await self._tftp_read(host, port, filename)
            if content is not None:
                files_found.append({
                    "filename": filename,
                    "size": len(content),
                    "preview": content[:200],
                })

        if files_found:
            is_traversal = any("../" in f["filename"] for f in files_found)

            ev = Evidence(
                extra={
                    "host": host,
                    "files_found": [f["filename"] for f in files_found],
                    "total_size": sum(f["size"] for f in files_found),
                },
            )

            severity = Severity.CRITICAL if is_traversal else Severity.HIGH
            self.new_finding(
                title=f"TFTP Unauthenticated File Access — {host}:69 ({len(files_found)} files)",
                severity=severity,
                description=(
                    f"TFTP server on {host}:69 serves files without authentication. "
                    f"Files retrieved: {', '.join(f['filename'] for f in files_found[:5])}.\n\n"
                    "TFTP has NO authentication mechanism by design. Any file within the "
                    "TFTP root is accessible to any network user. Found files may contain:\n"
                    "  - Network device configurations (router/switch passwords)\n"
                    "  - PXE boot images (bootloader compromise)\n"
                    "  - System files (via directory traversal)"
                    + ("\n\nDIRECTORY TRAVERSAL CONFIRMED — files outside TFTP root are accessible!" if is_traversal else "")
                ),
                reproduction_steps=[
                    f"tftp {host}",
                    f"get {files_found[0]['filename']}",
                    f"# Or: atftp --get --remote-file {files_found[0]['filename']} {host}",
                ],
                remediation=(
                    "1. Disable TFTP if not required\n"
                    "2. Restrict TFTP root directory (chroot)\n"
                    "3. Firewall: limit UDP 69 to specific management hosts\n"
                    "4. Use SFTP or SCP instead for file transfers\n"
                    "5. Move sensitive configs out of TFTP root"
                ),
                references=["CWE-306", "CWE-22"] if is_traversal else ["CWE-306"],
                evidence=ev,
                cvss_v31_vector=CVSS_TRAVERSAL if is_traversal else CVSS_NOAUTH,
                cvss_v40_vector=CVSS40_TRAVERSAL if is_traversal else CVSS40_NOAUTH,
                port=69, service="tftp", target=host,
            )

    async def _tftp_read(
        self, host: str, port: int, filename: str
    ) -> str | None:
        """Attempt to read a file via TFTP RRQ (UDP)."""
        try:
            # Build TFTP RRQ packet: opcode(2) + filename + \0 + mode + \0
            rrq = struct.pack(">H", 1)  # opcode 1 = RRQ
            rrq += filename.encode() + b"\x00"
            rrq += b"octet\x00"

            loop = asyncio.get_event_loop()

            # Create a future to collect the response
            response_data = bytearray()
            response_received = asyncio.Event()
            error_received = asyncio.Event()

            class TFTPProtocol(asyncio.DatagramProtocol):
                def datagram_received(self, data, addr):
                    nonlocal response_data
                    if len(data) >= 4:
                        opcode = struct.unpack(">H", data[:2])[0]
                        if opcode == 3:  # DATA
                            response_data.extend(data[4:])
                            response_received.set()
                        elif opcode == 5:  # ERROR
                            error_received.set()

            transport, protocol = await asyncio.wait_for(
                loop.create_datagram_endpoint(
                    TFTPProtocol,
                    remote_addr=(host, port),
                ),
                timeout=3,
            )

            transport.sendto(rrq)

            try:
                done, pending = await asyncio.wait(
                    [
                        asyncio.ensure_future(response_received.wait()),
                        asyncio.ensure_future(error_received.wait()),
                    ],
                    timeout=3,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                for p in pending:
                    p.cancel()
            except Exception:
                pass
            finally:
                transport.close()

            if response_received.is_set() and response_data:
                return response_data.decode(errors="ignore")
            return None
        except Exception:
            return None


class TestTftpAudit:
    def test_probe_files(self) -> None:
        assert "running-config" in PROBE_FILES
        assert any("../" in f for f in PROBE_FILES)

    def test_cvss(self) -> None:
        assert CVSS_NOAUTH.startswith("CVSS:3.1")
        assert CVSS40_NOAUTH.startswith("CVSS:4.0")

    def test_phase(self) -> None:
        assert TftpAudit.PHASE == 5
