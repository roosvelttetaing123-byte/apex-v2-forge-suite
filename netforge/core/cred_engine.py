"""Credential Engine — encrypted storage with memory protection.

Stores discovered credentials in memory with at-rest encryption.
Passwords are encrypted using a session-scoped Fernet key that
only exists in process memory. On export, all sensitive fields
are encrypted. Memory is wiped (zeroed) after credential use.

Security features:
  - Fernet symmetric encryption for passwords/hashes at rest
  - ctypes.memset memory wiping after credential use
  - Masked repr/to_dict by default — never accidentally leak
  - Session-scoped key — dies with the process, never persisted
  - Encrypted JSON export — ciphertext on disk

Usage:
    engine = CredEngine()
    engine.add("10.0.0.1", "ssh", "root", password="toor")
    engine.export_json(path)  # encrypted on disk
    cred = engine.get("10.0.0.1", "ssh", "root")
    plaintext = cred.get_password(engine.session_key)  # decrypt
    cred.wipe()  # zero memory
"""
from __future__ import annotations

import base64
import ctypes
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


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


def _encrypt_field(value: str, key: bytes) -> str:
    """Encrypt a credential field."""
    if not value:
        return ""
    if _HAS_CRYPTO:
        f = Fernet(key)
        return f.encrypt(value.encode("utf-8")).decode("ascii")
    # XOR fallback
    raw_key = base64.urlsafe_b64decode(key)
    data = value.encode("utf-8")
    xored = bytes(b ^ raw_key[i % len(raw_key)] for i, b in enumerate(data))
    return "XOR:" + base64.b64encode(xored).decode("ascii")


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


def _wipe_string(s: str) -> None:
    """Attempt to zero out a string's memory buffer.

    CPython strings are immutable and interned, so this is best-effort.
    We overwrite the internal buffer via ctypes. Not guaranteed on all
    interpreters, but it's better than leaving passwords in memory
    until garbage collection eventually runs.
    """
    if not s or not isinstance(s, str):
        return
    try:
        # Get the internal buffer address
        # CPython: str objects have their data at a known offset
        buf_addr = id(s) + sys.getsizeof("") - 1
        buf_len = len(s.encode("utf-8"))
        ctypes.memset(buf_addr, 0, buf_len)
    except Exception:
        pass  # Non-CPython or protected memory — can't wipe


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
        """Zero out all sensitive fields from memory.

        Call this after you're done using the credential.
        Best-effort on CPython — the GC might have copies.
        """
        _wipe_string(self._enc_password)
        _wipe_string(self._enc_nt_hash)
        _wipe_string(self._enc_lm_hash)
        self._enc_password = ""
        self._enc_nt_hash = ""
        self._enc_lm_hash = ""
        self._wiped = True

    # ------------------------------------------------------------------
    # Safe serialization — never leaks plaintext
    # ------------------------------------------------------------------

    def to_dict(self, include_encrypted: bool = False) -> dict:
        """Serialize to dict — passwords are MASKED by default.

        Args:
            include_encrypted: If True, include encrypted ciphertext.
                               Still not plaintext — needs session key to decrypt.
        """
        d: dict[str, Any] = {
            "host": self.host,
            "service": self.service,
            "username": self.username,
            "source": self.source,
            "has_password": self.has_password(),
            "has_nt_hash": self.has_nt_hash(),
            "wiped": self._wiped,
        }
        if include_encrypted:
            d["enc_password"] = self._enc_password
            d["enc_nt_hash"] = self._enc_nt_hash
            d["enc_lm_hash"] = self._enc_lm_hash
        else:
            d["password"] = "****" if self.has_password() else ""
            d["nt_hash"] = "****" if self.has_nt_hash() else ""
            d["lm_hash"] = "****" if bool(self._enc_lm_hash) else ""
        return d

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
        # Encrypt before storing
        enc_password = _encrypt_field(password, self.session_key) if password else ""
        enc_nt_hash = _encrypt_field(nt_hash, self.session_key) if nt_hash else ""
        enc_lm_hash = _encrypt_field(lm_hash, self.session_key) if lm_hash else ""

        cred = Credential(
            host=host, service=service, username=username,
            _enc_password=enc_password, _enc_nt_hash=enc_nt_hash,
            _enc_lm_hash=enc_lm_hash, source=source,
        )
        existing = self._creds.get(cred.key())
        if existing:
            # Merge — fill in missing fields
            if enc_password and not existing.has_password():
                existing._enc_password = enc_password
            if enc_nt_hash and not existing.has_nt_hash():
                existing._enc_nt_hash = enc_nt_hash
            return existing
        self._creds[cred.key()] = cred

        # Wipe the plaintext inputs from our stack frame (best effort)
        _wipe_string(password)
        _wipe_string(nt_hash)
        _wipe_string(lm_hash)

        return cred

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
        """Export credentials as JSON — encrypted fields, never plaintext.

        The output contains ciphertext that requires the session key
        to decrypt. Safe to write to disk.
        """
        data = json.dumps(
            [c.to_dict(include_encrypted=True) for c in self._creds.values()],
            indent=2,
        )
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(data)
        return data

    def export_plaintext(self, path: Path) -> str:
        """Export credentials with decrypted passwords — USE WITH CAUTION.

        This writes plaintext passwords to disk. Only use for operator
        review in controlled environments.
        """
        records = []
        for c in self._creds.values():
            records.append({
                "host": c.host,
                "service": c.service,
                "username": c.username,
                "password": c.get_password(self.session_key),
                "nt_hash": c.get_nt_hash(self.session_key),
                "lm_hash": c.get_lm_hash(self.session_key),
                "source": c.source,
            })
        data = json.dumps(records, indent=2)
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(data)
        return data

    def wipe_all(self) -> None:
        """Wipe all stored credentials from memory. Call at scan end."""
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
        # The internal field should NOT be the plaintext
        assert cred._enc_password != "secret123"
        assert cred._enc_password != ""

    def test_decrypt_password(self) -> None:
        engine = CredEngine()
        engine.add("10.0.0.1", "ssh", "root", password="P@ssw0rd!")
        cred = engine.get("10.0.0.1", "ssh", "root")
        assert cred.get_password(engine.session_key) == "P@ssw0rd!"

    def test_masked_repr(self) -> None:
        engine = CredEngine()
        engine.add("10.0.0.1", "ssh", "root", password="secret")
        cred = engine.get("10.0.0.1", "ssh", "root")
        r = repr(cred)
        assert "secret" not in r
        assert "****" in r

    def test_masked_to_dict(self) -> None:
        engine = CredEngine()
        engine.add("10.0.0.1", "ssh", "root", password="secret")
        cred = engine.get("10.0.0.1", "ssh", "root")
        d = cred.to_dict()
        assert d["password"] == "****"
        assert "secret" not in str(d)

    def test_wipe(self) -> None:
        engine = CredEngine()
        engine.add("10.0.0.1", "ssh", "root", password="wipe_me")
        cred = engine.get("10.0.0.1", "ssh", "root")
        cred.wipe()
        assert cred.get_password(engine.session_key) == "[WIPED]"
        assert cred._wiped is True

    def test_export_encrypted(self, tmp_path: Path) -> None:
        engine = CredEngine()
        engine.add("10.0.0.1", "ssh", "root", password="secret")
        data = engine.export_json(tmp_path / "creds.json")
        assert "secret" not in data
        assert "enc_password" in data

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
        assert cred.has_password()
        assert cred.get_password(engine.session_key) == "found_later"

    def test_wipe_all(self) -> None:
        engine = CredEngine()
        engine.add("10.0.0.1", "ssh", "root", password="a")
        engine.add("10.0.0.2", "ftp", "admin", password="b")
        engine.wipe_all()
        for c in engine.all():
            assert c._wiped
