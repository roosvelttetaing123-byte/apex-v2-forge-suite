"""VNC Auditor — auth bypass, weak passwords, RFB protocol version check.

Tests:
  - VNC authentication bypass (no-auth allowed)
  - Weak/default VNC password testing
  - RFB protocol version detection
  - Screen capture risk assessment
"""
from __future__ import annotations

import asyncio
import hashlib
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_NOAUTH     = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_NOAUTH   = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_WEAK_PASS  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
CVSS40_WEAK_PASS = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"

VNC_PORTS = [5900, 5901, 5902, 5903]

# VNC Security Types
SEC_NONE = 1
SEC_VNC_AUTH = 2
SEC_TIGHT = 16

WEAK_PASSWORDS = ["password", "vnc", "123456", "admin", "1234", "test", "root", ""]


class VncAudit(BaseModule):
    """VNC security auditor — auth bypass, weak passwords, protocol checks."""

    NAME        = "vnc_audit"
    DESCRIPTION = "VNC: auth bypass, weak passwords, RFB protocol version, screen capture risk"
    PHASE       = 4
    TAGS        = ["vnc", "services", "remote-access", "cwe-287"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])
        for host in hosts[:30]:
            if not self.check_scope(host):
                continue
            for port in VNC_PORTS:
                await self.rate_limit()
                if await self._port_open(host, port):
                    await self._audit_vnc(host, port)

        return self._make_result(start)

    async def _audit_vnc(self, host: str, port: int) -> None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )

            # Read RFB protocol version
            version_data = await asyncio.wait_for(reader.read(12), timeout=5)
            version_str = version_data.decode(errors="ignore").strip()

            if not version_str.startswith("RFB"):
                writer.close()
                return

            # Send our protocol version (match theirs)
            writer.write(version_data)
            await writer.drain()

            # Read security types
            sec_data = await asyncio.wait_for(reader.read(64), timeout=5)
            writer.close()

            if not sec_data:
                return

            # Parse security types (RFB 3.7+ format)
            if len(sec_data) >= 1:
                num_types = sec_data[0]
                sec_types = list(sec_data[1:1 + num_types])

                # Check for no-auth (SecurityType 1)
                if SEC_NONE in sec_types:
                    ev = Evidence(
                        request_raw=f"RFB {version_str} → {host}:{port}",
                        response_raw=f"Security types: {sec_types} (1=None, 2=VNC Auth)",
                        extra={
                            "host": host, "rfb_version": version_str,
                            "security_types": sec_types,
                            "no_auth": True,
                        },
                    )
                    self.new_finding(
                        title=f"VNC No Authentication Required — {host}:{port} ({version_str})",
                        severity=Severity.CRITICAL,
                        description=(
                            f"VNC server on {host}:{port} ({version_str}) allows connections "
                            "WITHOUT any authentication. Anyone can:\n"
                            "  - View the remote desktop in real-time\n"
                            "  - Control keyboard and mouse\n"
                            "  - Capture screenshots of sensitive content\n"
                            "  - Install malware or create backdoor accounts"
                        ),
                        reproduction_steps=[
                            f"vncviewer {host}::{port}",
                            "# No password required — direct desktop access",
                        ],
                        remediation=(
                            "1. Enable VNC authentication (set a strong password)\n"
                            "   TigerVNC: vncpasswd\n"
                            "   RealVNC: Set password in server settings\n"
                            "2. Use SSH tunneling for VNC: ssh -L 5900:localhost:5900 user@host\n"
                            "3. Firewall: block VNC ports (5900-5903) from untrusted networks\n"
                            "4. Consider VNC alternatives: RDP with NLA, Chrome Remote Desktop"
                        ),
                        references=["CWE-287", "CWE-306"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_NOAUTH,
                        cvss_v40_vector=CVSS40_NOAUTH,
                        mitre_attack=["TA0001/T1021.005"],
                        port=port, service="vnc", target=host,
                    )
                elif SEC_VNC_AUTH in sec_types:
                    # Try weak passwords
                    await self._try_weak_passwords(host, port, version_data)

        except Exception as exc:
            self.log.debug("VNC audit failed on %s:%d: %s", host, port, exc)

    async def _try_weak_passwords(
        self, host: str, port: int, version_data: bytes
    ) -> None:
        """Test common weak VNC passwords via VNC DES challenge-response."""
        for password in WEAK_PASSWORDS:
            await self.rate_limit()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=5
                )

                # Protocol exchange
                server_ver = await asyncio.wait_for(reader.read(12), timeout=3)
                writer.write(server_ver)
                await writer.drain()

                # Read security types
                sec_data = await asyncio.wait_for(reader.read(64), timeout=3)
                num_types = sec_data[0]
                sec_types = list(sec_data[1:1 + num_types])

                if SEC_VNC_AUTH not in sec_types:
                    writer.close()
                    break

                # Select VNC Auth
                writer.write(bytes([SEC_VNC_AUTH]))
                await writer.drain()

                # Read 16-byte challenge
                challenge = await asyncio.wait_for(reader.readexactly(16), timeout=3)

                # VNC DES auth: reverse bits in each byte of key, encrypt challenge
                key_bytes = password.encode("latin-1")[:8].ljust(8, b"\x00")
                # Bit-reverse each byte for VNC DES
                reversed_key = bytes(
                    int(f"{b:08b}"[::-1], 2) for b in key_bytes
                )

                from Crypto.Cipher import DES  # type: ignore
                des = DES.new(reversed_key, DES.MODE_ECB)
                response = des.encrypt(challenge[:8]) + des.encrypt(challenge[8:16])

                writer.write(response)
                await writer.drain()

                # Read auth result (4 bytes: 0 = OK, 1 = failed)
                result = await asyncio.wait_for(reader.readexactly(4), timeout=3)
                writer.close()

                if result == b"\x00\x00\x00\x00":
                    ev = Evidence(
                        request_raw=f"VNC DES auth with password: {password!r}",
                        extra={"host": host, "password": password or "(empty)"},
                    )
                    self.new_finding(
                        title=f"VNC Weak Password — {host}:{port} (password: {password or 'empty'})",
                        severity=Severity.HIGH,
                        description=(
                            f"VNC on {host}:{port} is protected by a weak password: {password or '(empty)'}. "
                            "VNC passwords are limited to 8 characters and use single-DES encryption, "
                            "making brute force trivial."
                        ),
                        reproduction_steps=[
                            f"vncviewer {host}::{port}",
                            f"Password: {password}",
                        ],
                        remediation="Set a strong VNC password (max 8 chars). Use SSH tunnel for encryption.",
                        references=["CWE-521", "CWE-287"],
                        evidence=ev,
                        cvss_v31_vector=CVSS_WEAK_PASS,
                        cvss_v40_vector=CVSS40_WEAK_PASS,
                        mitre_attack=["TA0001/T1021.005"],
                        port=port, service="vnc", target=host,
                    )
                    return  # Found weak password, stop testing
            except ImportError:
                self.log.debug("pycryptodome not installed — skipping VNC password test")
                return
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


class TestVncAudit:
    def test_ports(self) -> None:
        assert 5900 in VNC_PORTS
        assert 5901 in VNC_PORTS

    def test_security_types(self) -> None:
        assert SEC_NONE == 1
        assert SEC_VNC_AUTH == 2

    def test_cvss(self) -> None:
        assert CVSS_NOAUTH.startswith("CVSS:3.1")
        assert CVSS40_NOAUTH.startswith("CVSS:4.0")

    def test_phase(self) -> None:
        assert VncAudit.PHASE == 4
