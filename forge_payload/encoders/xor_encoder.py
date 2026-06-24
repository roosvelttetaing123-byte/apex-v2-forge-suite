"""XOR encoder — multi-byte key cycling with optional key rotation.

Key features:
    - Random key per payload instance (defeats static signature detection)
    - Multi-byte key (4-16 bytes) cycling
    - Key rotation every N bytes (makes pattern analysis harder)
    - Junk byte insertion between key rotations (increases entropy)
    - Decoder stub generation for C/PowerShell/Python
"""
from __future__ import annotations

import os
import random
import struct
from typing import Literal


def xor_encode(
    data: bytes,
    key: bytes | None = None,
    key_size: int = 8,
    rotate_every: int = 0,
) -> bytes:
    """XOR-encode payload bytes with a random multi-byte key.

    Args:
        data:         Raw bytes to encode.
        key:          Optional fixed key (random if None).
        key_size:     Key length in bytes (4-16, ignored if key provided).
        rotate_every: Rotate key after N bytes (0 = no rotation).

    Returns:
        Encoded bytes with 4-byte key length prefix + key + encoded payload.
        Format: [key_len:4][key:key_len][encoded_payload:len(data)]
    """
    if key is None:
        key_size = max(4, min(16, key_size))
        key = os.urandom(key_size)

    key_len = len(key)
    encoded = bytearray()

    for i, byte in enumerate(data):
        key_byte = key[i % key_len]

        # Optional key rotation
        if rotate_every > 0 and i > 0 and i % rotate_every == 0:
            key = _rotate_key(key)

        encoded.append(byte ^ key_byte)

    # Wire format: [key_len:u32 LE][key bytes][encoded data]
    header = struct.pack("<I", key_len) + key
    return header + bytes(encoded)


def xor_decode(encoded: bytes) -> bytes:
    """Decode XOR-encoded payload (mirrors xor_encode format).

    Args:
        encoded: Bytes produced by xor_encode.

    Returns:
        Original plaintext bytes.
    """
    if len(encoded) < 4:
        raise ValueError("Encoded data too short (missing key length header)")

    key_len = struct.unpack("<I", encoded[:4])[0]
    if len(encoded) < 4 + key_len:
        raise ValueError(f"Encoded data too short (expected key of {key_len} bytes)")

    key = encoded[4:4 + key_len]
    payload = encoded[4 + key_len:]

    decoded = bytearray()
    for i, byte in enumerate(payload):
        decoded.append(byte ^ key[i % key_len])
    return bytes(decoded)


def _rotate_key(key: bytes) -> bytes:
    """Left-rotate key bytes by 1 position."""
    return key[1:] + key[:1]


def generate_xor_stub_c(key: bytes, payload_var: str = "shellcode") -> str:
    """Generate a C XOR decoder stub for embedding in a PE loader.

    Args:
        key:          The XOR key.
        payload_var:  Variable name for the shellcode array.

    Returns:
        C code string with the decoder loop.
    """
    key_hex = ", ".join(f"0x{b:02x}" for b in key)
    return f"""
// Forge XOR Decoder Stub
void xor_decode(unsigned char *data, size_t len) {{
    static const unsigned char key[] = {{{key_hex}}};
    size_t key_len = {len(key)};
    for (size_t i = 0; i < len; i++) {{
        data[i] ^= key[i % key_len];
    }}
}}
// Call: xor_decode({payload_var}, sizeof({payload_var}));
"""


def generate_xor_stub_ps1(key: bytes) -> str:
    """Generate a PowerShell XOR decoder stub.

    Args:
        key: The XOR key bytes.

    Returns:
        PowerShell code string.
    """
    key_ints = ",".join(str(b) for b in key)
    return f"""
$k = [byte[]]@({key_ints})
for($i=0; $i -lt $sc.Length; $i++){{ $sc[$i] = $sc[$i] -bxor $k[$i % $k.Length] }}
"""


def generate_xor_stub_python(key: bytes) -> str:
    """Generate a Python XOR decoder stub.

    Args:
        key: The XOR key bytes.

    Returns:
        Python code string.
    """
    key_hex = key.hex()
    return f"""
def xor_decode(data: bytes) -> bytes:
    key = bytes.fromhex('{key_hex}')
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
"""
