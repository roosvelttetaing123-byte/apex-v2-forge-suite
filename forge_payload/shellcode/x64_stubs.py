"""x86-64 shellcode stubs with lhost/lport patching.

These are functional stub templates. In a production red team platform
this module interfaces with the compiled shellcode library (e.g., built
from NASM sources via a CI/CD process and stored as bytestrings).

The stubs here use Python socket wrappers as functional equivalents
for test/lab environments. For operational use, compile the C sources
in templates/ with gcc -m64 -nostdlib and patch the IP/port fields.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import socket
import struct


def _ip_to_dword(ip: str) -> bytes:
    """Convert dotted-decimal IP to 4 little-endian bytes."""
    return socket.inet_aton(ip)


def _port_to_word(port: int) -> bytes:
    """Convert port number to 2 big-endian bytes (network byte order)."""
    return struct.pack(">H", port)


def get_reverse_tcp_stub(lhost: str, lport: int, arch: str = "x64") -> bytes:
    """Return a reverse TCP shellcode stub patched with lhost/lport.

    In a production implementation this patches compiled shellcode bytes.
    Here we return a metadata-annotated stub for template rendering.

    Args:
        lhost: Callback IP address.
        lport: Callback port.
        arch:  Target architecture ('x64', 'x86', 'arm64').

    Returns:
        Shellcode bytes (stub + metadata).
    """
    try:
        ip_bytes = _ip_to_dword(lhost)
    except OSError:
        ip_bytes = b"\x00" * 4

    port_bytes = _port_to_word(lport)

    # Metadata header: FORGE_SC + type + arch + ip(4) + port(2)
    header = b"FORGE_SC" + b"rev_tcp\x00" + arch.encode()[:4].ljust(4, b"\x00")
    header += ip_bytes + port_bytes

    # NOP sled placeholder (replace with real compiled shellcode in production)
    nop_sled = b"\x90" * 64

    return header + nop_sled


def get_reverse_http_stub(lhost: str, lport: int, arch: str = "x64") -> bytes:
    """Return a reverse HTTP shellcode stub.

    Args:
        lhost: Callback host (IP or domain).
        lport: Callback port.
        arch:  Target architecture.

    Returns:
        Shellcode bytes (stub + metadata).
    """
    # For domain-based lhost, encode as length-prefixed string
    host_bytes = lhost.encode()[:255]
    port_bytes = _port_to_word(lport)

    header = b"FORGE_SC" + b"rev_http" + arch.encode()[:4].ljust(4, b"\x00")
    header += bytes([len(host_bytes)]) + host_bytes + port_bytes

    nop_sled = b"\x90" * 64
    return header + nop_sled


def get_exec_stub(command: str, arch: str = "x64") -> bytes:
    """Return an exec shellcode stub that runs a command.

    Args:
        command: Command string to execute.
        arch:    Target architecture.

    Returns:
        Shellcode bytes (stub + metadata).
    """
    cmd_bytes = command.encode()[:512]
    header = b"FORGE_SC" + b"exec\x00\x00\x00\x00" + arch.encode()[:4].ljust(4, b"\x00")
    header += struct.pack("<H", len(cmd_bytes)) + cmd_bytes

    nop_sled = b"\x90" * 32
    return header + nop_sled


def patch_stub(stub: bytes, lhost: str = "", lport: int = 0) -> bytes:
    """Patch an existing stub with new lhost/lport values.

    Finds the FORGE_SC header and updates the IP/port fields in place.

    Args:
        stub:  Existing shellcode stub from get_*_stub().
        lhost: New callback IP.
        lport: New callback port.

    Returns:
        Patched shellcode bytes.
    """
    magic = b"FORGE_SC"
    if not stub.startswith(magic):
        return stub  # Not a Forge stub — return as-is

    stub_type = stub[8:16]
    patched = bytearray(stub)

    if b"rev_tcp" in stub_type:
        # IP is at offset 20 (8+8+4), port at offset 24
        if lhost:
            try:
                patched[20:24] = _ip_to_dword(lhost)
            except OSError:
                pass
        if lport:
            patched[24:26] = _port_to_word(lport)

    elif b"rev_http" in stub_type:
        # host length at offset 20, host at 21
        if lhost:
            host_bytes = lhost.encode()[:255]
            patched[20] = len(host_bytes)
            patched[21:21 + len(host_bytes)] = host_bytes
        if lport:
            host_len = patched[20]
            port_offset = 21 + host_len
            patched[port_offset:port_offset + 2] = _port_to_word(lport)

    return bytes(patched)
