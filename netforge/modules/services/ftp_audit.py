"""FTP Auditor — anonymous login, bounce attack, cleartext credential detection.

Tests:
  - Anonymous FTP login (user: anonymous / ftp)
  - Directory listing and file access on anonymous sessions
  - FTP bounce scan (PORT command relay through vulnerable server)
  - Cleartext credential warning (FTP sends user/pass in plaintext)
  - Banner grabbing for version disclosure
  - Write access test on anonymous sessions
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

CVSS_ANON       = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
CVSS40_ANON     = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"
CVSS_CLEARTEXT  = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N"
CVSS40_CLEARTEXT = "CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
CVSS_BOUNCE     = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:N/A:N"
CVSS40_BOUNCE   = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:L/SI:N/SA:N"

ANON_USERS = ["anonymous", "ftp"]
ANON_PASSWORDS = ["", "ftp@ftp.com", "anonymous@", "guest"]


class FtpAudit(BaseModule):
    """FTP security auditor — anonymous access, bounce, cleartext protocol."""

    NAME        = "ftp_audit"
    DESCRIPTION = "FTP: anonymous login, bounce scan, cleartext creds, banner version"
    PHASE       = 4
    TAGS        = ["ftp", "services", "cleartext", "cwe-287", "cwe-319"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])
        port = self.config.extra.get("ftp_port", 21)

        for host in hosts[:30]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            if not await self._port_open(host, port):
                continue
            await self._audit_host(host, port)

        return self._make_result(start)

    async def _audit_host(self, host: str, port: int) -> None:
        banner = await self._grab_banner(host, port)
        if banner is None:
            return

        # Report cleartext protocol
        self.new_finding(
            title=f"FTP Cleartext Protocol — {host}:{port}",
            severity=Severity.MEDIUM,
            description=(
                f"FTP service on {host}:{port} transmits credentials and data in cleartext. "
                "Any network-positioned attacker can sniff usernames, passwords, and file "
                "contents via ARP spoofing, MITM, or passive monitoring."
            ),
            reproduction_steps=[
                f"tcpdump -i any -A port {port} and host {host}",
                f"Connect: ftp {host} — observe plaintext USER/PASS in capture",
            ],
            remediation=(
                "Replace FTP with SFTP (SSH-based) or FTPS (FTP over TLS).\n"
                "If FTP must remain, enforce FTPS with AUTH TLS before USER command.\n"
                "vsftpd: ssl_enable=YES, force_local_data_ssl=YES\n"
                "ProFTPD: TLSRequired on"
            ),
            references=["CWE-319", "CWE-523"],
            evidence=Evidence(extra={"host": host, "port": port, "banner": banner}),
            cvss_v31_vector=CVSS_CLEARTEXT,
            cvss_v40_vector=CVSS40_CLEARTEXT,
            port=port, service="ftp", target=host,
        )

        # Report version disclosure in banner
        if any(c.isdigit() for c in banner):
            self.new_finding(
                title=f"FTP Banner Version Disclosure — {host}",
                severity=Severity.LOW,
                description=f"FTP banner discloses software version: {banner!r}",
                reproduction_steps=[f"echo 'QUIT' | nc {host} {port}"],
                remediation="Suppress version from FTP banner. vsftpd: ftpd_banner=Welcome. ProFTPD: ServerIdent off",
                references=["CWE-200"],
                evidence=Evidence(extra={"banner": banner}),
                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cvss_v40_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
                port=port, service="ftp", target=host,
            )

        # Test anonymous login
        await self._test_anonymous(host, port, banner)

        # Test FTP bounce
        await self._test_bounce(host, port)

    async def _grab_banner(self, host: str, port: int) -> str | None:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )
            data = await asyncio.wait_for(reader.readline(), timeout=5)
            banner = data.decode(errors="ignore").strip()
            writer.close()
            return banner
        except Exception:
            return None

    async def _test_anonymous(self, host: str, port: int, banner: str) -> None:
        for user in ANON_USERS:
            for password in ANON_PASSWORDS:
                await self.rate_limit()
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port), timeout=5
                    )
                    welcome = await asyncio.wait_for(reader.readline(), timeout=5)

                    writer.write(f"USER {user}\r\n".encode())
                    await writer.drain()
                    resp = await asyncio.wait_for(reader.readline(), timeout=5)
                    resp_str = resp.decode(errors="ignore").strip()

                    if not resp_str.startswith("331"):
                        writer.close()
                        continue

                    writer.write(f"PASS {password}\r\n".encode())
                    await writer.drain()
                    resp = await asyncio.wait_for(reader.readline(), timeout=5)
                    resp_str = resp.decode(errors="ignore").strip()

                    if resp_str.startswith("230"):
                        # Login succeeded — enumerate directories
                        dirs = await self._list_dirs(reader, writer)
                        writable = await self._test_write(reader, writer)

                        writer.write(b"QUIT\r\n")
                        await writer.drain()
                        writer.close()

                        severity = Severity.HIGH if writable else Severity.MEDIUM
                        ev = Evidence(
                            request_raw=f"USER {user} / PASS {password or '(empty)'}",
                            response_raw=resp_str,
                            extra={
                                "host": host, "user": user,
                                "directories": dirs[:20],
                                "writable": writable,
                            },
                        )
                        self.new_finding(
                            title=f"FTP Anonymous Login — {host}:{port} ({'WRITABLE' if writable else 'read-only'})",
                            severity=severity,
                            description=(
                                f"Anonymous FTP login succeeded on {host}:{port} "
                                f"(user={user!r}, pass={password or '(empty)'}). "
                                + (f"Root listing: {', '.join(dirs[:5])}. " if dirs else "")
                                + ("WRITE ACCESS confirmed — attackers can upload malware/webshells. " if writable else "")
                                + "Anonymous FTP exposes files to unauthenticated users."
                            ),
                            reproduction_steps=[
                                f"ftp {host}",
                                f"Name: {user}",
                                f"Password: {password or '(press enter)'}",
                                "dir",
                            ],
                            remediation=(
                                "Disable anonymous FTP access:\n"
                                "  vsftpd: anonymous_enable=NO\n"
                                "  ProFTPD: <Anonymous> block — remove or set AnonRequirePassword on\n"
                                "  IIS: Remove 'Anonymous Authentication' from FTP site\n"
                                + ("  URGENT: Remove write access immediately!" if writable else "")
                            ),
                            references=["CWE-287", "CWE-306", "MITRE T1078"],
                            evidence=ev,
                            cvss_v31_vector=CVSS_ANON,
                            cvss_v40_vector=CVSS40_ANON,
                            mitre_attack=["TA0001/T1078.001"],
                            port=port, service="ftp", target=host,
                        )
                        return  # One finding per host is enough
                    writer.close()
                except Exception:
                    pass

    async def _list_dirs(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> list[str]:
        """Send PASV + LIST to get directory listing."""
        try:
            writer.write(b"PASV\r\n")
            await writer.drain()
            pasv_resp = await asyncio.wait_for(reader.readline(), timeout=5)
            pasv_str = pasv_resp.decode(errors="ignore").strip()
            if not pasv_str.startswith("227"):
                return []

            # Parse PASV response: 227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)
            import re
            m = re.search(r"\((\d+,\d+,\d+,\d+,\d+,\d+)\)", pasv_str)
            if not m:
                return []
            parts = m.group(1).split(",")
            data_port = int(parts[4]) * 256 + int(parts[5])
            data_host = ".".join(parts[:4])

            data_reader, data_writer = await asyncio.wait_for(
                asyncio.open_connection(data_host, data_port), timeout=5
            )
            writer.write(b"LIST\r\n")
            await writer.drain()
            await asyncio.wait_for(reader.readline(), timeout=5)  # 150 response

            listing = await asyncio.wait_for(data_reader.read(4096), timeout=5)
            data_writer.close()
            await asyncio.wait_for(reader.readline(), timeout=5)  # 226 response

            lines = listing.decode(errors="ignore").strip().split("\n")
            return [line.strip().split()[-1] for line in lines if line.strip()]
        except Exception:
            return []

    async def _test_write(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> bool:
        """Test write access by attempting MKD then RMD."""
        test_dir = ".forge_write_test"
        try:
            writer.write(f"MKD {test_dir}\r\n".encode())
            await writer.drain()
            resp = await asyncio.wait_for(reader.readline(), timeout=5)
            resp_str = resp.decode(errors="ignore").strip()
            if resp_str.startswith("257"):
                # Clean up
                writer.write(f"RMD {test_dir}\r\n".encode())
                await writer.drain()
                await asyncio.wait_for(reader.readline(), timeout=5)
                return True
            return False
        except Exception:
            return False

    async def _test_bounce(self, host: str, port: int) -> None:
        """Test FTP bounce scan by issuing PORT to a third-party address."""
        await self.rate_limit()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )
            await asyncio.wait_for(reader.readline(), timeout=5)

            writer.write(b"USER anonymous\r\n")
            await writer.drain()
            resp = await asyncio.wait_for(reader.readline(), timeout=5)
            if not resp.decode(errors="ignore").startswith("331"):
                writer.close()
                return

            writer.write(b"PASS ftp@test.com\r\n")
            await writer.drain()
            resp = await asyncio.wait_for(reader.readline(), timeout=5)
            if not resp.decode(errors="ignore").startswith("230"):
                writer.close()
                return

            # Try PORT to a different address (127.0.0.1:80)
            writer.write(b"PORT 127,0,0,1,0,80\r\n")
            await writer.drain()
            resp = await asyncio.wait_for(reader.readline(), timeout=5)
            resp_str = resp.decode(errors="ignore").strip()

            writer.write(b"QUIT\r\n")
            await writer.drain()
            writer.close()

            if resp_str.startswith("200"):
                ev = Evidence(
                    request_raw="PORT 127,0,0,1,0,80",
                    response_raw=resp_str,
                    extra={"host": host, "bounce_possible": True},
                )
                self.new_finding(
                    title=f"FTP Bounce Attack Possible — {host}:{port}",
                    severity=Severity.MEDIUM,
                    description=(
                        f"FTP server on {host} accepts PORT commands to arbitrary addresses. "
                        "Attackers can use this server as a proxy to scan internal networks "
                        "(FTP bounce scan), bypass firewalls, or relay connections."
                    ),
                    reproduction_steps=[
                        f"nmap -b anonymous@{host} <internal_target>",
                        f"# Manual: ftp {host} → PORT 10,0,0,1,0,80 → LIST",
                    ],
                    remediation=(
                        "Disable PORT to non-client addresses:\n"
                        "  vsftpd: pasv_promiscuous=NO (default)\n"
                        "  ProFTPD: AllowForeignAddress off"
                    ),
                    references=["CWE-441", "CVE-1999-0017"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_BOUNCE,
                    cvss_v40_vector=CVSS40_BOUNCE,
                    port=port, service="ftp", target=host,
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


class TestFtpAudit:
    def test_anon_users(self) -> None:
        assert "anonymous" in ANON_USERS
        assert "ftp" in ANON_USERS

    def test_cvss_vectors(self) -> None:
        assert CVSS_ANON.startswith("CVSS:3.1")
        assert CVSS40_ANON.startswith("CVSS:4.0")
        assert CVSS_CLEARTEXT.startswith("CVSS:3.1")
        assert CVSS_BOUNCE.startswith("CVSS:3.1")

    def test_phase(self) -> None:
        assert FtpAudit.PHASE == 4
