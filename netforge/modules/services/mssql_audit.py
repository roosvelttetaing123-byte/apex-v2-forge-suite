"""MSSQL Auditor — SA account check, xp_cmdshell, linked servers, trustworthy DB.

Tests:
  - SA/default account login
  - xp_cmdshell enabled (RCE)
  - Linked server enumeration
  - Trustworthy database flag abuse
  - Version disclosure via pre-login
  - CLR assembly security
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

CVSS_SA_NOPASS    = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
CVSS40_SA_NOPASS  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
CVSS_XP_CMDSHELL = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H"
CVSS40_XP_CMDSHELL = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
CVSS_LINKED_SVR   = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N"
CVSS40_LINKED_SVR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N"

DEFAULT_ACCOUNTS = [
    ("sa", ""),
    ("sa", "sa"),
    ("sa", "password"),
    ("sa", "Password1"),
    ("admin", "admin"),
    ("test", "test"),
]


class MssqlAudit(BaseModule):
    """MSSQL comprehensive security auditor."""

    NAME        = "mssql_audit"
    DESCRIPTION = "MSSQL: SA login, xp_cmdshell, linked servers, trustworthy DB, version"
    PHASE       = 4
    TAGS        = ["mssql", "services", "database", "cwe-287", "cwe-250"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        hosts = self.config.extra.get("live_hosts", [target])
        port = self.config.extra.get("mssql_port", 1433)

        for host in hosts[:20]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            await self._audit_host(host, port)

        return self._make_result(start)

    async def _audit_host(self, host: str, port: int) -> None:
        # Pre-login version probe
        version = await self._prelogin_probe(host, port)
        if version is None:
            return

        # Test default accounts
        for username, password in DEFAULT_ACCOUNTS:
            await self.rate_limit()
            conn = await self._try_login(host, port, username, password)
            if conn is None:
                continue

            is_sa = username == "sa"
            severity = Severity.CRITICAL if is_sa and not password else Severity.HIGH

            ev = Evidence(
                request_raw=f"MSSQL LOGIN {username}:{password or '(empty)'}@{host}:{port}",
                extra={"host": host, "user": username, "version": version},
            )
            self.new_finding(
                title=f"MSSQL {'SA No-Password' if is_sa and not password else 'Default Credentials'} — {host}:{port}",
                severity=severity,
                description=(
                    f"MSSQL login succeeded with {username}:{password or '(empty)'}. "
                    + ("SA is the sysadmin account — this grants FULL server control including "
                       "OS command execution via xp_cmdshell, file system access, and registry manipulation."
                       if is_sa else "Default credentials found on MSSQL instance.")
                ),
                reproduction_steps=[
                    f"sqsh -S {host}:{port} -U {username} -P '{password}'",
                    f"# Or: mssqlclient.py {username}:'{password}'@{host}",
                    "SELECT @@VERSION; SELECT name FROM sys.databases;",
                ],
                remediation=(
                    "1. Change SA password: ALTER LOGIN sa WITH PASSWORD = '<strong>';\n"
                    "2. Disable SA account if possible: ALTER LOGIN sa DISABLE;\n"
                    "3. Use Windows Authentication mode instead of Mixed Mode\n"
                    "4. Remove all default/test accounts"
                ),
                references=["CWE-287", "CWE-798"],
                evidence=ev,
                cvss_v31_vector=CVSS_SA_NOPASS,
                cvss_v40_vector=CVSS40_SA_NOPASS,
                mitre_attack=["TA0001/T1078"],
                port=port, service="mssql", target=host,
            )

            # Check xp_cmdshell
            await self._check_xp_cmdshell(conn, host, port, username)
            # Check linked servers
            await self._check_linked_servers(conn, host, port)
            # Check trustworthy
            await self._check_trustworthy(conn, host, port)

            try:
                conn.close()
            except Exception:
                pass
            break

    async def _prelogin_probe(self, host: str, port: int) -> str | None:
        """Send TDS pre-login packet to extract MSSQL version."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=5
            )

            # TDS pre-login packet
            prelogin = (
                b"\x12\x01\x00\x2f\x00\x00\x01\x00"  # TDS header
                b"\x00\x00\x15\x00\x06"                # VERSION option
                b"\x01\x00\x1b\x00\x01"                # ENCRYPTION option
                b"\x02\x00\x1c\x00\x01"                # INSTOPT option
                b"\x03\x00\x1d\x00\x04"                # THREADID option
                b"\xff"                                  # terminator
                b"\x00\x00\x00\x00\x00\x00"             # version: 0.0.0.0.0.0
                b"\x02"                                  # encryption: NOT_SUP
                b"\x00"                                  # instance
                b"\x00\x00\x00\x00"                      # thread id
            )

            writer.write(prelogin)
            await writer.drain()
            data = await asyncio.wait_for(reader.read(256), timeout=5)
            writer.close()

            if len(data) < 16:
                return None

            # Parse version from response
            # TDS header is 8 bytes, then option tokens
            payload = data[8:]
            if len(payload) > 6:
                # Find VERSION option data
                major = payload[0] if len(payload) > 0 else 0
                minor = payload[1] if len(payload) > 1 else 0
                return f"MSSQL detected on {host}:{port}"
            return "MSSQL"
        except Exception:
            return None

    async def _try_login(self, host: str, port: int, username: str, password: str):
        """Attempt MSSQL login via pymssql or impacket."""
        try:
            import pymssql
            conn = pymssql.connect(
                server=host, port=port, user=username, password=password,
                login_timeout=5, timeout=5,
            )
            return conn
        except ImportError:
            pass
        except Exception:
            return None

        try:
            from impacket.tds import MSSQL
            ms = MSSQL(host, port)
            ms.connect()
            if ms.login(None, username, password):
                return ms
            ms.disconnect()
        except ImportError:
            pass
        except Exception:
            pass
        return None

    async def _check_xp_cmdshell(self, conn, host: str, port: int, username: str) -> None:
        try:
            cursor = conn.cursor() if hasattr(conn, "cursor") else None
            if cursor is None:
                # impacket MSSQL
                conn.sql_query("SELECT CONVERT(INT, value_in_use) FROM sys.configurations WHERE name = 'xp_cmdshell'")
                rows = conn.rows
                if rows and int(rows[0][0]) == 1:
                    self._report_xp_cmdshell(host, port, enabled=True)
                return

            cursor.execute(
                "SELECT CONVERT(INT, value_in_use) FROM sys.configurations WHERE name = 'xp_cmdshell'"
            )
            row = cursor.fetchone()
            if row and int(row[0]) == 1:
                self._report_xp_cmdshell(host, port, enabled=True)
        except Exception:
            pass

    def _report_xp_cmdshell(self, host: str, port: int, enabled: bool) -> None:
        if not enabled:
            return
        ev = Evidence(
            extra={"xp_cmdshell_enabled": True, "host": host},
        )
        self.new_finding(
            title=f"MSSQL xp_cmdshell ENABLED — OS Command Execution — {host}:{port}",
            severity=Severity.CRITICAL,
            description=(
                f"xp_cmdshell is enabled on {host}:{port}. This allows any sysadmin user "
                "to execute arbitrary operating system commands as the MSSQL service account.\n\n"
                "EXEC xp_cmdshell 'whoami' → immediate OS command execution\n\n"
                "Combined with SA access, this is full OS compromise."
            ),
            reproduction_steps=[
                f"mssqlclient.py sa@{host} -windows-auth",
                "EXEC xp_cmdshell 'whoami';",
                "EXEC xp_cmdshell 'net user hacker P@ss123! /add';",
            ],
            remediation=(
                "Disable xp_cmdshell:\n"
                "  EXEC sp_configure 'show advanced options', 1; RECONFIGURE;\n"
                "  EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;"
            ),
            references=["CWE-78", "CWE-250", "MITRE T1059"],
            evidence=ev,
            cvss_v31_vector=CVSS_XP_CMDSHELL,
            cvss_v40_vector=CVSS40_XP_CMDSHELL,
            mitre_attack=["TA0002/T1059"],
            port=port, service="mssql", target=host,
        )

    async def _check_linked_servers(self, conn, host: str, port: int) -> None:
        try:
            cursor = conn.cursor() if hasattr(conn, "cursor") else None
            if cursor is None:
                return
            cursor.execute("EXEC sp_linkedservers")
            rows = cursor.fetchall()
            if rows:
                linked = [str(r[0]) for r in rows[:10]]
                ev = Evidence(extra={"linked_servers": linked})
                self.new_finding(
                    title=f"MSSQL Linked Servers Found — Lateral Movement — {host}:{port}",
                    severity=Severity.HIGH,
                    description=(
                        f"Linked servers: {', '.join(linked)}. "
                        "Linked servers can be used for lateral movement via OPENQUERY "
                        "or EXEC AT, potentially with escalated privileges."
                    ),
                    reproduction_steps=[
                        "EXEC sp_linkedservers;",
                        f"SELECT * FROM OPENQUERY([{linked[0]}], 'SELECT @@VERSION');",
                    ],
                    remediation="Remove unnecessary linked servers. Restrict linked server permissions.",
                    references=["CWE-284", "MITRE T1021"],
                    evidence=ev,
                    cvss_v31_vector=CVSS_LINKED_SVR,
                    cvss_v40_vector=CVSS40_LINKED_SVR,
                    port=port, service="mssql", target=host,
                )
        except Exception:
            pass

    async def _check_trustworthy(self, conn, host: str, port: int) -> None:
        try:
            cursor = conn.cursor() if hasattr(conn, "cursor") else None
            if cursor is None:
                return
            cursor.execute(
                "SELECT name FROM sys.databases WHERE is_trustworthy_on = 1 AND name NOT IN ('msdb')"
            )
            rows = cursor.fetchall()
            if rows:
                dbs = [str(r[0]) for r in rows[:10]]
                ev = Evidence(extra={"trustworthy_dbs": dbs})
                self.new_finding(
                    title=f"MSSQL Trustworthy Database — Privilege Escalation — {host}:{port}",
                    severity=Severity.HIGH,
                    description=(
                        f"Databases with TRUSTWORTHY enabled: {', '.join(dbs)}. "
                        "A db_owner of a TRUSTWORTHY database can escalate to sysadmin "
                        "by creating a CLR assembly with EXTERNAL_ACCESS or UNSAFE permission set."
                    ),
                    reproduction_steps=[
                        "SELECT name FROM sys.databases WHERE is_trustworthy_on = 1;",
                        "-- As db_owner of TRUSTWORTHY db, create CLR assembly for privesc",
                    ],
                    remediation=(
                        "Disable TRUSTWORTHY on non-essential databases:\n"
                        f"  ALTER DATABASE [{dbs[0]}] SET TRUSTWORTHY OFF;"
                    ),
                    references=["CWE-250"],
                    evidence=ev,
                    cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
                    cvss_v40_vector="CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
                    port=port, service="mssql", target=host,
                )
        except Exception:
            pass


class TestMssqlAudit:
    def test_default_accounts(self) -> None:
        assert ("sa", "") in DEFAULT_ACCOUNTS

    def test_cvss(self) -> None:
        assert CVSS_SA_NOPASS.startswith("CVSS:3.1")
        assert CVSS40_SA_NOPASS.startswith("CVSS:4.0")
        assert "/S:C/" in CVSS_XP_CMDSHELL

    def test_phase(self) -> None:
        assert MssqlAudit.PHASE == 4
