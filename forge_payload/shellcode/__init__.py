"""Shellcode stubs and position-independent code (PIC) generation.

Available stubs:
    - x64_reverse_tcp: x86-64 reverse TCP shellcode stub
    - x64_reverse_http: x86-64 reverse HTTP shellcode stub
    - x64_exec: Execute a command via CreateProcessA (x64)

In production these would be compiled from NASM/FASM sources.
The stubs here are templates that get patched with lhost/lport at generation time.
"""

from forge_payload.shellcode.x64_stubs import (
    get_reverse_tcp_stub,
    get_reverse_http_stub,
    get_exec_stub,
    patch_stub,
)

__all__ = [
    "get_reverse_tcp_stub",
    "get_reverse_http_stub",
    "get_exec_stub",
    "patch_stub",
]
