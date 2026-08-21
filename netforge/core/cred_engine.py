"""Credential Engine — encrypted storage with bounded secret lifetimes.

Stores discovered credentials in memory with at-rest encryption.
Passwords are encrypted using a session-scoped Fernet key that
only exists in process memory. On export, all sensitive fields
are represented by protected references. Owned transient buffers
are cleared after credential intake.

Security features:
  - Fernet symmetric encryption for passwords/hashes at rest
  - Owned mutable plaintext buffers cleared immediately after encryption
  - Masked repr/to_dict by default — never accidentally leak
  - Session-scoped key — dies with the process, never persisted
  - Protected-reference JSON export — no secret material on disk

Usage:
    engine = CredEngine()
    engine.add("10.0.0.1", "ssh", "root", password="toor")
    engine.export_json(path)  # protected references only
    cred = engine.get("10.0.0.1", "ssh", "root")
    plaintext = cred.get_password(engine.session_key)  # decrypt
    cred.wipe()  # release stored ciphertext references
"""
from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from common.artifact_io import atomic_write_bytes, ensure_private_directory


# Fernet is preferred but we provide a fallback
try:
    from cryptography.fernet import Fernet
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


def _generate_session_key() -> bytes:
    """Generate a session-scoped encryption key.

    This key only exists in memory. When the process exits, it's gone.
    We don't persist it — deliberately. If you need to decrypt exported
    creds later, you must save the key yourself (we'll warn you).
    """
    if _HAS_CRYPTO:
        return Fernet.generate_key()
    return base64.urlsafe_b64encode(os.urandom(32))


def _owned_plaintext_buffer(value: str | None) -> bytearray:
    """Copy one plaintext input into memory this module can deterministically clear."""
    if value is None:
        return bytearray()
    if not isinstance(value, str):
        raise TypeError("credential fields must be strings")
    return bytearray(value, "utf-8")


def _wipe_buffer(value: bytearray) -> None:
    """Overwrite and release an owned mutable buffer without touching ``str`` memory."""
    if not isinstance(value, bytearray):
        raise TypeError("only owned bytearray buffers may be wiped")
    if value:
        value[:] = b"\x00" * len(value)
        value.clear()


def _encrypt_field(value: bytearray | str, key: bytes) -> str:
    """Encrypt a credential field from an owned mutable plaintext buffer."""
    # Keep the historical private helper callable by direct integrations while
    # ensuring even that path obtains and clears its own mutable copy.
    if isinstance(value, str):
        owned = _owned_plaintext_buffer(value)
        try:
            return _encrypt_field(owned, key)
        finally:
            _wipe_buffer(owned)
    if not value:
        return ""
    if not isinstance(value, bytearray):
        raise TypeError("credential plaintext must use an owned bytearray")
    if _HAS_CRYPTO:
        f = Fernet(key)
        # Fernet currently requires ``bytes``. Keep the unavoidable immutable
        # conversion inside this call while retaining and clearing our owned
        # input buffer in ``CredEngine.add``'s finally block.
        return f.encrypt(bytes(value)).decode("ascii")
    # XOR fallback
    raw_key = bytearray(base64.urlsafe_b64decode(key))
    xored = bytearray(len(value))
    try:
        for index, octet in enumerate(value):
            xored[index] = octet ^ raw_key[index % len(raw_key)]
        return "XOR:" + base64.b64encode(xored).decode("ascii")
    finally:
        _wipe_buffer(xored)
        _wipe_buffer(raw_key)


def _decrypt_field(encrypted: str, key: bytes) -> str:
    """Decrypt a credential field."""
    if not encrypted:
        return ""
    if _HAS_CRYPTO and not encrypted.startswith("XOR:"):
        f = Fernet(key)
        return f.decrypt(encrypted.encode("ascii")).decode("utf-8")
    # XOR fallback
    if encrypted.startswith("XOR:"):
        encrypted = encrypted[4:]
    raw_key = base64.urlsafe_b64decode(key)
    xored = base64.b64decode(encrypted.encode("ascii"))
    decrypted = bytes(b ^ raw_key[i % len(raw_key)] for i, b in enumerate(xored))
    return decrypted.decode("utf-8")


def _wipe_string(value: str) -> None:
    """Compatibility shim that deliberately leaves immutable strings untouched.

    Callers should pass plaintext through :func:`_owned_plaintext_buffer` and
    :func:`_wipe_buffer`; this legacy name remains available without unsafe
    raw memory writes into CPython string storage.
    """
    if not isinstance(value, str):
        return


def _ensure_owner_only_directory(directory: Path) -> None:
    """Validate/create a no-follow owner-only directory chain."""
    ensure_private_directory(directory)


def _atomic_owner_only_write(path: Path, payload: bytes) -> None:
    """Atomically replace one path through a pinned no-follow parent."""
    atomic_write_bytes(path, payload, mode=0o600)


@dataclass
class Credential:
    """A discovered credential with encrypted storage.

    Passwords and hashes are stored encrypted in memory.
    Use get_password(key) to decrypt, then wipe() when done.
    """
    host: str
    service: str
    username: str
    _enc_password: str = field(default="", repr=False)
    _enc_nt_hash: str  = field(default="", repr=False)
    _enc_lm_hash: str  = field(default="", repr=False)
    source: str        = ""
    _wiped: bool       = field(default=False, repr=False)

    def key(self) -> str:
        return f"{self.host}:{self.service}:{self.username}"

    # ------------------------------------------------------------------
    # Decryption — explicit, never automatic
    # ------------------------------------------------------------------

    def get_password(self, session_key: bytes) -> str:
        """Decrypt and return the plaintext password."""
        if self._wiped:
            return "[WIPED]"
        return _decrypt_field(self._enc_password, session_key)

    def get_nt_hash(self, session_key: bytes) -> str:
        """Decrypt and return the NT hash."""
        if self._wiped:
            return "[WIPED]"
        return _decrypt_field(self._enc_nt_hash, session_key)

    def get_lm_hash(self, session_key: bytes) -> str:
        """Decrypt and return the LM hash."""
        if self._wiped:
            return "[WIPED]"
        return _decrypt_field(self._enc_lm_hash, session_key)

    def has_password(self) -> bool:
        """Check if a password is stored (without decrypting)."""
        return bool(self._enc_password) and not self._wiped

    def has_nt_hash(self) -> bool:
        """Check if an NT hash is stored."""
        return bool(self._enc_nt_hash) and not self._wiped

    # ------------------------------------------------------------------
    # Memory protection
    # ------------------------------------------------------------------

    def wipe(self) -> None:
        """Release all ciphertext references and make the credential unusable.

        Python strings are immutable, so this method deliberately never writes
        through their object addresses. Plaintext encryption intake is instead
        handled through owned mutable buffers that are cleared in ``add``.
        """
        self._enc_password = ""
        self._enc_nt_hash = ""
        self._enc_lm_hash = ""
        self._wiped = True

    # ------------------------------------------------------------------
    # Safe serialization — never leaks plaintext
    # ------------------------------------------------------------------

    def to_dict(self, include_encrypted: bool = False) -> dict:
        """Serialize only non-secret metadata and an opaque reference.

        ``include_encrypted`` is retained for call compatibility but ciphertext
        is no longer allowed across an ordinary JSON/event/report boundary.
        """
        from common.action_authorization import protected_credential_reference

        return {
            "host": self.host,
            "service": self.service,
            "username": self.username,
            "source": self.source,
            "has_password": self.has_password(),
            "has_nt_hash": self.has_nt_hash(),
            "wiped": self._wiped,
            "credential_reference": protected_credential_reference(
                {"credential_key": self.key(), "source": self.source}
            ),
        }

    def __repr__(self) -> str:
        """Never show passwords in repr."""
        pw = "****" if self.has_password() else "(none)"
        return f"Credential({self.host}:{self.service} {self.username}:{pw})"


class CredEngine:
    """Encrypted credential store with deduplication and memory protection."""

    def __init__(self, session_key: bytes | None = None) -> None:
        self._creds: dict[str, Credential] = {}
        self.session_key = session_key or _generate_session_key()

    def add(
        self,
        host: str,
        service: str,
        username: str,
        password: str = "",
        nt_hash: str = "",
        lm_hash: str = "",
        source: str = "",
    ) -> Credential:
        """Add or update a credential — encrypts sensitive fields immediately."""
        plaintext_buffers: list[bytearray] = []
        try:
            # ``str`` is caller-owned and immutable. Copy each value into a
            # mutable buffer under this method's ownership before encryption.
            for value in (password, nt_hash, lm_hash):
                plaintext_buffers.append(_owned_plaintext_buffer(value))
            password_buffer, nt_hash_buffer, lm_hash_buffer = plaintext_buffers

            enc_password = (
                _encrypt_field(password_buffer, self.session_key)
                if password_buffer
                else ""
            )
            enc_nt_hash = (
                _encrypt_field(nt_hash_buffer, self.session_key)
                if nt_hash_buffer
                else ""
            )
            enc_lm_hash = (
                _encrypt_field(lm_hash_buffer, self.session_key)
                if lm_hash_buffer
                else ""
            )

            credential_key = f"{host}:{service}:{username}"
            existing = self._creds.get(credential_key)
            if existing:
                # Merge only fields not already present. The finally block runs
                # for both merged and ignored duplicate inputs.
                if enc_password and not existing.has_password():
                    existing._enc_password = enc_password
                if enc_nt_hash and not existing.has_nt_hash():
                    existing._enc_nt_hash = enc_nt_hash
                if enc_lm_hash and not existing._enc_lm_hash:
                    existing._enc_lm_hash = enc_lm_hash
                return existing

            cred = Credential(
                host=host,
                service=service,
                username=username,
                _enc_password=enc_password,
                _enc_nt_hash=enc_nt_hash,
                _enc_lm_hash=enc_lm_hash,
                source=source,
            )
            self._creds[credential_key] = cred
            return cred
        finally:
            for plaintext_buffer in plaintext_buffers:
                _wipe_buffer(plaintext_buffer)

    def get(self, host: str, service: str, username: str) -> Credential | None:
        """Look up a credential by host:service:username."""
        return self._creds.get(f"{host}:{service}:{username}")

    def for_service(self, service: str) -> list[Credential]:
        return [c for c in self._creds.values() if c.service.lower() == service.lower()]

    def for_host(self, host: str) -> list[Credential]:
        return [c for c in self._creds.values() if c.host == host]

    def all(self) -> list[Credential]:
        return list(self._creds.values())

    def export_json(self, path: Path | None = None) -> str:
        """Return protected references and metadata, never secret material."""
        data = json.dumps(
            [credential.to_dict() for credential in self._creds.values()],
            indent=2,
        )
        if path:
            _atomic_owner_only_write(path, data.encode("utf-8"))
        return data

    def export_plaintext(self, path: Path) -> str:
        """Plaintext credential export is intentionally disabled."""
        raise RuntimeError("plaintext credential export is disabled")

    def wipe_all(self) -> None:
        """Release every stored ciphertext field. Call at scan end."""
        for cred in self._creds.values():
            cred.wipe()

    def __len__(self) -> int:
        return len(self._creds)

    def __repr__(self) -> str:
        return f"CredEngine({len(self)} credentials, encrypted)"


# ======================================================================
# Tests
# ======================================================================

class TestCredEngine:
    """Unit tests for encrypted credential engine."""

    def test_add_and_retrieve(self) -> None:
        engine = CredEngine()
        engine.add("10.0.0.1", "ssh", "root", password="toor")
        cred = engine.get("10.0.0.1", "ssh", "root")
        assert cred is not None
        assert cred.username == "root"
        assert cred.has_password()

    def test_password_encrypted_in_memory(self) -> None:
        engine = CredEngine()
        engine.add("10.0.0.1", "ssh", "admin", password="secret123")
        cred = engine.get("10.0.0.1", "ssh", "admin")
        assert cred is not None
        # The internal field should NOT be the plaintext
        assert cred._enc_password != "secret123"
        assert cred._enc_password != ""

    def test_decrypt_password(self) -> None:
        engine = CredEngine()
        engine.add("10.0.0.1", "ssh", "root", password="P@ssw0rd!")
        cred = engine.get("10.0.0.1", "ssh", "root")
        assert cred is not None
        assert cred.get_password(engine.session_key) == "P@ssw0rd!"

    def test_masked_repr(self) -> None:
        engine = CredEngine()
        engine.add("10.0.0.1", "ssh", "root", password="secret")
        cred = engine.get("10.0.0.1", "ssh", "root")
        assert cred is not None
        r = repr(cred)
        assert "secret" not in r
        assert "****" in r

    def test_masked_to_dict(self) -> None:
        engine = CredEngine()
        engine.add("10.0.0.1", "ssh", "root", password="secret")
        cred = engine.get("10.0.0.1", "ssh", "root")
        assert cred is not None
        d = cred.to_dict()
        assert "password" not in d
        assert "enc_password" not in d
        assert d["credential_reference"].startswith("cred:sha256:")
        assert "secret" not in str(d)

    def test_wipe(self) -> None:
        engine = CredEngine()
        engine.add("10.0.0.1", "ssh", "root", password="wipe_me")
        cred = engine.get("10.0.0.1", "ssh", "root")
        assert cred is not None
        cred.wipe()
        assert cred.get_password(engine.session_key) == "[WIPED]"
        assert cred._wiped is True

    def test_export_encrypted(self, tmp_path: Path) -> None:
        engine = CredEngine()
        engine.add("10.0.0.1", "ssh", "root", password="secret")
        data = engine.export_json(tmp_path / "creds.json")
        assert "secret" not in data
        assert "credential_reference" in data
        assert "enc_password" not in data

    def test_dedup(self) -> None:
        engine = CredEngine()
        engine.add("10.0.0.1", "ssh", "root", password="pass1")
        engine.add("10.0.0.1", "ssh", "root", password="pass2")
        assert len(engine) == 1  # Deduped

    def test_merge_fills_missing(self) -> None:
        engine = CredEngine()
        engine.add("10.0.0.1", "ssh", "root")  # No password
        engine.add("10.0.0.1", "ssh", "root", password="found_later")
        cred = engine.get("10.0.0.1", "ssh", "root")
        assert cred is not None
        assert cred.has_password()
        assert cred.get_password(engine.session_key) == "found_later"

    def test_wipe_all(self) -> None:
        engine = CredEngine()
        engine.add("10.0.0.1", "ssh", "root", password="a")
        engine.add("10.0.0.2", "ftp", "admin", password="b")
        engine.wipe_all()
        for c in engine.all():
            assert c._wiped
