"""Telnet Auditor — cleartext protocol detection, default credentials, banner grabbing.

Tests:
  - Cleartext protocol warning (all creds sent in plain)
  - Default/common credential testing
  - Banner grabbing for version/device identification
  - Cisco/router/switch default login detection
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

CVSS_CLEARTEXT = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_CLEARTEXT = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_DEFAULT_CRED = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS40_DEFAULT_CRED = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("root", "root"),
    ("root", ""),
    ("cisco", "cisco"),
    ("enable", ""),
    ("user", "user"),
    ("guest", "guest"),
]


class TelnetAudit(BaseModule):
    """Telnet security auditor — cleartext, default creds, banner."""

    NAME        = "telnet_audit"
    DESCRIPTION = "Telnet: cleartext protocol, default credentials, device identification"
    PHASE       = 4
    TAGS        = ["telnet", "services", "cleartext", "cwe-319", "cwe-287"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])
        port = self.config.extra.get("telnet_port", 23)

        for host in hosts[:30]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            if await self._port_open(host, port):
                await self._audit_host(host, port)

        return self._make_result(start)

    async def _audit_host(self, host: str, port: int) -> None:
        banner = await self._grab_banner(host, port)
        if banner is None:
            return

        # Cleartext protocol warning
        self.new_finding(
            title=f"Telnet Cleartext Protocol — {host}:{port}",
            severity=Severity.HIGH,
            description=(
                f"Telnet service on {host}:{port} transmits ALL data including credentials "
                "in cleartext. Any network-positioned attacker can capture usernames, "
                "passwords, and complete session content via passive sniffing."
            ),
            reproduction_steps=[
                f"tcpdump -i any -A port {port} and host {host}",
                f"telnet {host} {port}",
                "Login with credentials — observe plaintext capture",
            ],
            remediation=(
                "Replace Telnet with SSH on all devices:\n"
                "  Cisco: line vty 0 4 → transport input ssh\n"
                "  Linux: systemctl disable telnetd; systemctl enable sshd\n"
                "  Windows: Disable Telnet Server feature"
            ),
            references=["CWE-319", "CWE-523"],
            evidence=Evidence(extra={"host": host, "port": port, "banner": banner}),
            cvss_v31_vector=CVSS_CLEARTEXT,
            cvss_v40_vector=CVSS40_CLEARTEXT,
            port=port, service="telnet", target=host,
        )

        # Test default credentials
        for username, password in DEFAULT_CREDS:
            await self.rate_limit()
            success = await self._try_login(host, port, username, password)
            if success:
                ev = Evidence(
                    request_raw=f"Telnet LOGIN {username}:{password or '(empty)'}",
                    extra={"host": host, "username": username, "banner": banner},
                )
                self.new_finding(
                    title=f"Telnet Default Credentials — {username}@{host}:{port}",
                    severity=Severity.CRITICAL,
                    description=(
                        f"Telnet login with {username}:{password or '(empty)'} succeeded on {host}:{port}. "
                        f"Banner: {banner!r}. "
                        "Combined with cleartext protocol, this is complete device compromise."
                    ),
                    reproduction_steps=[
                        f"telnet {host} {port}",
                        f"Login: {username}",
                        f"Password: {password or '(press enter)'}",
                    ],
                    remediation=(
                        "1. Change default credentials immediately\n"
                        "2. Replace Telnet with SSH\n"
                        "3. Implement account lockout policies"
                    ),
                    references=["CWE-287", "CWE-798"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_DEFAULT_CRED,
                    cvss_v40_vector=CVSS40_DEFAULT_CRED,
                    mitre_attack=["TA0001/T1078"],
                    port=port, service="telnet", target=host,
                )
                break

    async def _grab_banner(self, host: str, port: int) -> str | None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )
            # Read initial data (may include Telnet negotiation bytes)
            data = await asyncio.wait_for(reader.read(1024), timeout=5)
            writer.close()
            # Filter out Telnet IAC negotiations (bytes 0xFF ...)
            clean = bytearray()
            i = 0
            while i < len(data):
                if data[i] == 0xFF and i + 2 < len(data):
                    i += 3  # Skip IAC + command + option
                else:
                    clean.append(data[i])
                    i += 1
            banner = clean.decode(errors="ignore").strip()[:200]
            return banner if banner else "Telnet service (no banner)"
        except Exception:
            return None

    async def _try_login(
        self, host: str, port: int, username: str, password: str
    ) -> bool:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )
            # Wait for login prompt
            data = await asyncio.wait_for(reader.read(2048), timeout=5)
            text = data.decode(errors="ignore").lower()

            if "login" in text or "username" in text or "user" in text:
                writer.write(f"{username}\r\n".encode())
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=5)
                text = data.decode(errors="ignore").lower()

                if "password" in text or "pass" in text:
                    writer.write(f"{password}\r\n".encode())
                    await writer.drain()
                    data = await asyncio.wait_for(reader.read(2048), timeout=5)
                    text = data.decode(errors="ignore").lower()

                    writer.close()
                    # Success indicators
                    fail_indicators = ["incorrect", "failed", "denied", "invalid", "bad", "error"]
                    success_indicators = ["$", "#", ">", "welcome", "last login", "menu"]
                    if any(f in text for f in fail_indicators):
                        return False
                    if any(s in text for s in success_indicators):
                        return True
            writer.close()
            return False
        except Exception:
            return False

    async def _port_open(self, host: str, port: int) -> bool:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=3
            )
            writer.close()
            return True
        except Exception:
            return False


class TestTelnetAudit:
    def test_default_creds(self) -> None:
        users = [u for u, _ in DEFAULT_CREDS]
        assert "admin" in users
        assert "cisco" in users

    def test_cvss(self) -> None:
        assert CVSS_CLEARTEXT.startswith("CVSS:3.1")
        assert CVSS40_CLEARTEXT.startswith("CVSS:4.0")

    def test_phase(self) -> None:
        assert TelnetAudit.PHASE == 4
