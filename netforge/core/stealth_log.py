"""Stealth Log Handler — encrypted SQLite logging for OpSec stealth mode.

When OpSec profile is 'stealth', all log output is redirected from the
Rich console to an encrypted SQLite database. This prevents real-time
console output that network defenders could monitor via shoulder surfing,
screen capture, or terminal logging.

Post-scan, the operator can decrypt and review findings.

Usage:
    from netforge.core.stealth_log import StealthLogHandler, install_stealth_logging

    # Install stealth logging (replaces console handlers)
    session_key = install_stealth_logging(results_dir)

    # ... run scan ...

    # After scan: decrypt and dump
    dump_stealth_log(results_dir / "stealth.db", session_key)
"""
from __future__ import annotations

import base64
import json
import logging
import os
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger("forge.stealth_log")

# We use Fernet for encryption — same key system as cred_engine
try:
    from cryptography.fernet import Fernet
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


def _generate_session_key() -> bytes:
    """Generate a 32-byte Fernet-compatible session key.

    This key lives only in memory for the duration of the scan.
    It's never written to disk. When the process dies, the key is gone.
    """
    if _HAS_CRYPTO:
        return Fernet.generate_key()
    # Fallback: base64-encoded random bytes (still works for XOR, just less elegant)
    return base64.urlsafe_b64encode(os.urandom(32))


def _encrypt(data: str, key: bytes) -> str:
    """Encrypt a string with the session key."""
    if _HAS_CRYPTO:
        f = Fernet(key)
        return f.encrypt(data.encode("utf-8")).decode("ascii")
    # Fallback: simple XOR — not cryptographically ideal but better than plaintext
    raw_key = base64.urlsafe_b64decode(key)
    data_bytes = data.encode("utf-8")
    xored = bytes(b ^ raw_key[i % len(raw_key)] for i, b in enumerate(data_bytes))
    return base64.b64encode(xored).decode("ascii")


def _decrypt(encrypted: str, key: bytes) -> str:
    """Decrypt a string with the session key."""
    if _HAS_CRYPTO:
        f = Fernet(key)
        return f.decrypt(encrypted.encode("ascii")).decode("utf-8")
    # Fallback XOR
    raw_key = base64.urlsafe_b64decode(key)
    xored = base64.b64decode(encrypted.encode("ascii"))
    decrypted = bytes(b ^ raw_key[i % len(raw_key)] for i, b in enumerate(xored))
    return decrypted.decode("utf-8")


class StealthLogHandler(logging.Handler):
    """Logging handler that writes encrypted log records to SQLite.

    Each log record is JSON-serialized, encrypted with the session key,
    and stored in a SQLite database. No plaintext hits the console.
    """

    def __init__(self, db_path: Path, session_key: bytes) -> None:
        super().__init__()
        self._db_path = db_path
        self._key = session_key
        self._conn = sqlite3.connect(str(db_path))
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS stealth_log (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                ts       TEXT    NOT NULL,
                level    TEXT    NOT NULL,
                payload  TEXT    NOT NULL
            )
        """)
        self._conn.commit()
        self._record_count = 0

    def emit(self, record: logging.LogRecord) -> None:
        """Encrypt and store a log record."""
        try:
            entry = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname,
                "name": record.name,
                "module": getattr(record, "forge_module", ""),
                "message": record.getMessage(),
                "target": getattr(record, "target", ""),
            }
            plaintext = json.dumps(entry, default=str)
            encrypted = _encrypt(plaintext, self._key)
            self._conn.execute(
                "INSERT INTO stealth_log (ts, level, payload) VALUES (?, ?, ?)",
                (entry["ts"], record.levelname, encrypted),
            )
            # Batch commits every 50 records for performance
            self._record_count += 1
            if self._record_count % 50 == 0:
                self._conn.commit()
        except Exception:
            pass  # Stealth logging must never crash the scan

    def flush(self) -> None:
        """Commit pending records."""
        try:
            self._conn.commit()
        except Exception:
            pass

    def close(self) -> None:
        """Flush and close the database connection."""
        self.flush()
        self._conn.close()
        super().close()


def install_stealth_logging(
    results_dir: Path,
    session_key: bytes | None = None,
) -> bytes:
    """Replace all console log handlers with the stealth handler.

    Args:
        results_dir: Directory to store stealth.db.
        session_key: Optional pre-generated key. Auto-generates if None.

    Returns:
        The session key (needed for decryption later).
    """
    if session_key is None:
        session_key = _generate_session_key()

    db_path = results_dir / "stealth.db"
    stealth_handler = StealthLogHandler(db_path, session_key)
    stealth_handler.setLevel(logging.DEBUG)

    # Find all forge loggers and replace their console handlers
    root = logging.getLogger()
    for name in list(logging.Logger.manager.loggerDict.keys()):
        if not name.startswith("forge"):
            continue
        logger = logging.getLogger(name)
        # Remove Rich/console handlers, keep file handlers
        for handler in list(logger.handlers):
            # RichHandler is a console handler — suppress it
            handler_type = type(handler).__name__
            if handler_type in ("RichHandler", "StreamHandler"):
                logger.removeHandler(handler)
        logger.addHandler(stealth_handler)

    # Also install on root forge logger
    forge_root = logging.getLogger("forge")
    for handler in list(forge_root.handlers):
        handler_type = type(handler).__name__
        if handler_type in ("RichHandler", "StreamHandler"):
            forge_root.removeHandler(handler)
    forge_root.addHandler(stealth_handler)

    log.debug("Stealth logging installed → %s", db_path)
    return session_key


def dump_stealth_log(
    db_path: Path,
    session_key: bytes,
    output_path: Path | None = None,
    level_filter: str | None = None,
) -> list[dict]:
    """Decrypt and return all stealth log records.

    Args:
        db_path:      Path to stealth.db.
        session_key:  The session key used during the scan.
        output_path:  Optional file to write decrypted JSON.
        level_filter: Optional level filter ("INFO", "WARNING", "ERROR").

    Returns:
        List of decrypted log record dicts.
    """
    conn = sqlite3.connect(str(db_path))
    query = "SELECT ts, level, payload FROM stealth_log ORDER BY id"
    if level_filter:
        query = f"SELECT ts, level, payload FROM stealth_log WHERE level = ? ORDER BY id"
        rows = conn.execute(query, (level_filter.upper(),)).fetchall()
    else:
        rows = conn.execute(query).fetchall()
    conn.close()

    records: list[dict] = []
    for ts, level, encrypted_payload in rows:
        try:
            decrypted = _decrypt(encrypted_payload, session_key)
            record = json.loads(decrypted)
            records.append(record)
        except Exception:
            records.append({"ts": ts, "level": level, "message": "[DECRYPTION FAILED]"})

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(records, indent=2))

    return records


# ======================================================================
# Tests
# ======================================================================

class TestStealthLog:
    """Unit tests for stealth logging."""

    def test_encrypt_decrypt_roundtrip(self) -> None:
        key = _generate_session_key()
        original = "This is a secret log message with NTLMv2 hashes"
        encrypted = _encrypt(original, key)
        assert encrypted != original
        decrypted = _decrypt(encrypted, key)
        assert decrypted == original

    def test_handler_writes_to_db(self, tmp_path: Path) -> None:
        key = _generate_session_key()
        db_path = tmp_path / "test_stealth.db"
        handler = StealthLogHandler(db_path, key)
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="",
            lineno=0, msg="test message", args=(), exc_info=None,
        )
        handler.emit(record)
        handler.close()
        # Verify record exists
        conn = sqlite3.connect(str(db_path))
        rows = conn.execute("SELECT COUNT(*) FROM stealth_log").fetchone()
        assert rows[0] >= 1
        conn.close()

    def test_dump_decrypts(self, tmp_path: Path) -> None:
        key = _generate_session_key()
        db_path = tmp_path / "test_stealth.db"
        handler = StealthLogHandler(db_path, key)
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="",
            lineno=0, msg="sensitive credential data", args=(), exc_info=None,
        )
        handler.emit(record)
        handler.close()
        records = dump_stealth_log(db_path, key)
        assert len(records) >= 1
        assert "sensitive credential data" in records[0].get("message", "")

    def test_wrong_key_fails_gracefully(self, tmp_path: Path) -> None:
        key1 = _generate_session_key()
        key2 = _generate_session_key()
        db_path = tmp_path / "test_stealth.db"
        handler = StealthLogHandler(db_path, key1)
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="",
            lineno=0, msg="secret", args=(), exc_info=None,
        )
        handler.emit(record)
        handler.close()
        # Decrypt with wrong key
        records = dump_stealth_log(db_path, key2)
        assert len(records) >= 1
        # Should get decryption failed or garbled data, not crash
