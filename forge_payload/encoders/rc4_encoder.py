"""RC4 stream cipher encoder.

Used for legacy target compatibility where AES stubs are too large.
Key is random per payload. Wire format: [key_len:1][key:key_len][ciphertext].
"""
from __future__ import annotations

import os


def _rc4_ksa(key: bytes) -> list[int]:
    """RC4 Key Scheduling Algorithm."""
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    return s


def _rc4_prga(s: list[int], length: int) -> bytes:
    """RC4 Pseudo-Random Generation Algorithm."""
    i = j = 0
    output = bytearray()
    for _ in range(length):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        output.append(s[(s[i] + s[j]) % 256])
    return bytes(output)


def rc4_encode(data: bytes, key: bytes | None = None) -> bytes:
    """RC4-encrypt payload bytes.

    Args:
        data: Plaintext bytes.
        key:  Optional key (random 16 bytes if None).

    Returns:
        [key_len:u8][key][ciphertext]
    """
    if key is None:
        key = os.urandom(16)
    s = _rc4_ksa(key)
    keystream = _rc4_prga(s, len(data))
    ciphertext = bytes(a ^ b for a, b in zip(data, keystream))
    return bytes([len(key)]) + key + ciphertext


def rc4_decode(encoded: bytes) -> bytes:
    """Decode RC4-encrypted payload.

    Args:
        encoded: Bytes from rc4_encode.

    Returns:
        Original plaintext.
    """
    key_len = encoded[0]
    key = encoded[1:1 + key_len]
    ciphertext = encoded[1 + key_len:]
    s = _rc4_ksa(key)
    keystream = _rc4_prga(s, len(ciphertext))
    return bytes(a ^ b for a, b in zip(ciphertext, keystream))
