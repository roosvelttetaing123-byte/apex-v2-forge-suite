"""Forge C2 — Beacon Cryptographic Layer.

Handles all encryption for C2 communications:
- RSA-4096 key exchange (initial beacon registration)
- AES-256-GCM session encryption (all subsequent traffic)
- HMAC-SHA256 message authentication
- Automatic key rotation

FOR AUTHORIZED RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import struct
import time
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("forge.c2.crypto")


@dataclass
class SessionKeys:
    """Cryptographic session state for a single beacon."""
    session_id:     str
    aes_key:        bytes = field(repr=False)
    hmac_key:       bytes = field(repr=False)
    nonce_counter:  int = 0
    created_at:     float = field(default_factory=time.time)
    message_count:  int = 0
    max_messages:   int = 100          # Rotate after N messages
    max_age_hours:  float = 24.0       # Rotate after N hours

    def needs_rotation(self) -> bool:
        """Check if keys need rotation."""
        age_hours = (time.time() - self.created_at) / 3600
        return (
            self.message_count >= self.max_messages or
            age_hours >= self.max_age_hours
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "message_count": self.message_count,
            "needs_rotation": self.needs_rotation(),
        }


class BeaconCrypto:
    """Cryptographic operations for C2 beacon communication.

    Provides:
    - RSA keypair generation for server identity
    - AES-256-GCM encrypt/decrypt for session traffic
    - HMAC-SHA256 message authentication
    - Automatic key rotation management

    Usage::

        crypto = BeaconCrypto()
        session = crypto.create_session("beacon-001")

        # Encrypt a task
        ciphertext = crypto.encrypt(session, b'{"cmd": "whoami"}')

        # Decrypt a result
        plaintext = crypto.decrypt(session, ciphertext)
    """

    def __init__(self) -> None:
        """Initialize crypto engine and generate server keypair."""
        self._sessions: dict[str, SessionKeys] = {}
        self._server_key_pem: bytes | None = None
        self._server_pub_pem: bytes | None = None
        self._generate_server_keys()

    def _generate_server_keys(self) -> None:
        """Generate RSA-4096 keypair for server identity."""
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.hazmat.primitives import hashes, serialization

            private_key = rsa.generate_private_key(
                public_exponent=65537, key_size=4096,
            )
            self._server_key_pem = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
            self._server_pub_pem = private_key.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            log.info("RSA-4096 server keypair generated")
        except ImportError as exc:
            raise RuntimeError("cryptography is required for C2 crypto") from exc

    @property
    def server_public_key(self) -> bytes:
        """Server's RSA public key in PEM format."""
        return self._server_pub_pem or b""

    def create_session(self, beacon_id: str) -> SessionKeys:
        """Create a new encrypted session for a beacon.

        Generates fresh AES-256 and HMAC-SHA256 keys.

        Args:
            beacon_id: Unique beacon identifier.

        Returns:
            SessionKeys with fresh cryptographic material.
        """
        session = SessionKeys(
            session_id=beacon_id,
            aes_key=secrets.token_bytes(32),   # AES-256
            hmac_key=secrets.token_bytes(32),   # HMAC-SHA256
        )
        self._sessions[beacon_id] = session
        log.debug("Session created for beacon %s", beacon_id)
        return session

    def rotate_session(self, beacon_id: str) -> SessionKeys | None:
        """Rotate keys for an existing session.

        Returns new SessionKeys, or None if beacon not found.
        """
        if beacon_id not in self._sessions:
            return None
        old = self._sessions[beacon_id]
        new_session = self.create_session(beacon_id)
        log.info("Keys rotated for beacon %s (after %d messages)",
                 beacon_id, old.message_count)
        return new_session

    def encrypt(self, session: SessionKeys, plaintext: bytes) -> bytes:
        """Encrypt a message using AES-256-GCM.

        Message format: [4-byte nonce_counter][12-byte nonce][16-byte tag][ciphertext]

        Args:
            session:   Active session keys.
            plaintext: Data to encrypt.

        Returns:
            Encrypted message bytes.
        """
        session.nonce_counter += 1
        session.message_count += 1

        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            nonce = self._derive_nonce(session.aes_key, session.nonce_counter)
            aesgcm = AESGCM(session.aes_key)
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)

            # Pack: [counter:4][nonce:12][ciphertext_with_tag]
            message = struct.pack(">I", session.nonce_counter) + nonce + ciphertext

            # HMAC the entire message
            mac = hmac.new(session.hmac_key, message, hashlib.sha256).digest()
            return mac + message

        except ImportError as exc:
            raise RuntimeError("cryptography is required for C2 encryption") from exc

    def decrypt(self, session: SessionKeys, data: bytes) -> bytes | None:
        """Decrypt a message using AES-256-GCM.

        Args:
            session: Active session keys.
            data:    Encrypted message bytes.

        Returns:
            Decrypted plaintext, or None on failure.
        """
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM

            # Verify HMAC (first 32 bytes)
            if len(data) < 48:  # 32 HMAC + 4 counter + 12 nonce
                log.warning("Message too short")
                return None

            mac = data[:32]
            message = data[32:]
            expected_mac = hmac.new(session.hmac_key, message, hashlib.sha256).digest()
            if not hmac.compare_digest(mac, expected_mac):
                log.warning("HMAC verification failed for beacon %s", session.session_id)
                return None

            # Unpack: [counter:4][nonce:12][ciphertext_with_tag]
            counter = struct.unpack(">I", message[:4])[0]
            nonce = message[4:16]
            ciphertext = message[16:]

            aesgcm = AESGCM(session.aes_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext

        except ImportError as exc:
            raise RuntimeError("cryptography is required for C2 decryption") from exc
        except Exception as exc:
            log.warning("Decryption failed for beacon %s: %s",
                        session.session_id, exc)
            return None

    def encrypt_json(self, session: SessionKeys, data: dict[str, Any]) -> bytes:
        """Encrypt a JSON-serializable dict."""
        plaintext = json.dumps(data, separators=(",", ":"), default=str).encode()
        return self.encrypt(session, plaintext)

    def decrypt_json(self, session: SessionKeys, data: bytes) -> dict[str, Any] | None:
        """Decrypt and parse JSON."""
        plaintext = self.decrypt(session, data)
        if plaintext is None:
            return None
        try:
            return json.loads(plaintext)
        except json.JSONDecodeError:
            log.warning("JSON decode failed after decryption")
            return None

    def get_session(self, beacon_id: str) -> SessionKeys | None:
        """Get session keys for a beacon."""
        return self._sessions.get(beacon_id)

    def remove_session(self, beacon_id: str) -> None:
        """Remove session (beacon killed/dead)."""
        if beacon_id in self._sessions:
            # Wipe key material
            session = self._sessions.pop(beacon_id)
            _wipe_bytes(session.aes_key)
            _wipe_bytes(session.hmac_key)

    @staticmethod
    def _derive_nonce(key: bytes, counter: int) -> bytes:
        """Derive a unique 12-byte nonce from key + counter."""
        data = key[:16] + struct.pack(">Q", counter)
        return hashlib.sha256(data).digest()[:12]

def _wipe_bytes(data: bytes) -> None:
    """Best-effort memory wiping of key material."""
    try:
        import ctypes
        buf = (ctypes.c_char * len(data)).from_buffer_copy(data)
        ctypes.memset(buf, 0, len(data))
    except Exception:
        pass


class TestBeaconCrypto:
    """Unit tests for beacon_crypto."""

    def test_session_creation(self) -> None:
        crypto = BeaconCrypto()
        session = crypto.create_session("beacon-001")
        assert session.session_id == "beacon-001"
        assert len(session.aes_key) == 32
        assert len(session.hmac_key) == 32

    def test_encrypt_decrypt(self) -> None:
        crypto = BeaconCrypto()
        session = crypto.create_session("beacon-002")
        plaintext = b"Hello from beacon"
        ciphertext = crypto.encrypt(session, plaintext)
        assert ciphertext != plaintext
        result = crypto.decrypt(session, ciphertext)
        assert result == plaintext

    def test_json_round_trip(self) -> None:
        crypto = BeaconCrypto()
        session = crypto.create_session("beacon-003")
        data = {"cmd": "whoami", "args": [], "id": 42}
        encrypted = crypto.encrypt_json(session, data)
        decrypted = crypto.decrypt_json(session, encrypted)
        assert decrypted == data

    def test_key_rotation(self) -> None:
        crypto = BeaconCrypto()
        session = crypto.create_session("beacon-004")
        session.message_count = 100
        assert session.needs_rotation() is True
        new_session = crypto.rotate_session("beacon-004")
        assert new_session is not None
        assert new_session.message_count == 0

    def test_tampered_message(self) -> None:
        crypto = BeaconCrypto()
        session = crypto.create_session("beacon-005")
        ciphertext = crypto.encrypt(session, b"secret")
        # Tamper with HMAC
        tampered = b"\x00" * 32 + ciphertext[32:]
        result = crypto.decrypt(session, tampered)
        assert result is None
