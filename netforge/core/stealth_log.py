"""Owner-only encrypted session logging for NetForge's quiet console mode.

The database contains only centrally redacted records.  A short-lived session
key is retained by the handler as mutable memory and is wiped when the handler
is finalized.  Clear-text exports use the shared descriptor-anchored artifact
boundary and are redacted again so legacy rows cannot cross an ordinary output
boundary.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from common.artifact_io import (
    ArtifactBoundaryError,
    absolute_lexical_path,
    atomic_write_bytes,
    open_owner_only_file,
    open_private_directory,
    open_verified_regular_file_for_read,
)
from common.redaction import redact_value, redacted_json_dumps, redaction_filter

log = logging.getLogger("forge.stealth_log")


class StealthLogError(ValueError):
    """Fixed public failure for an unavailable session-log artifact."""


_STEALTH_LOG_FAILURE = "stealth log is unavailable"
_SQLITE_DESCRIPTOR_ROOTS = ("/proc/self/fd", "/dev/fd")
_STANDARD_RECORD_FIELDS = frozenset(logging.makeLogRecord({}).__dict__)


try:
    from cryptography.fernet import Fernet

    _HAS_CRYPTO = True
except ImportError:  # pragma: no cover - dependency gate covers this branch
    Fernet = None  # type: ignore[assignment,misc]
    _HAS_CRYPTO = False


def _wipe_bytearray(value: bytearray) -> None:
    """Best-effort overwrite followed by release of owned mutable material."""
    value[:] = b"\x00" * len(value)
    value.clear()


def _safe_close_descriptor(descriptor: int) -> None:
    if descriptor < 0:
        return
    try:
        os.close(descriptor)
    except Exception:
        pass


def _safe_close_connection(connection: sqlite3.Connection | None) -> None:
    if connection is None:
        return
    try:
        connection.close()
    except Exception:
        pass


def _sqlite_descriptor_path(descriptor: int) -> str:
    """Return the platform descriptor path used to pin a SQLite connection."""
    for root in _SQLITE_DESCRIPTOR_ROOTS:
        if os.path.isdir(root):
            return f"{root}/{descriptor}"
    raise StealthLogError(_STEALTH_LOG_FAILURE)


def _connect_owner_only_database(
    db_path: Path,
    *,
    read_only: bool,
) -> tuple[Path, sqlite3.Connection]:
    """Open SQLite through one verified descriptor without following links."""
    descriptor = -1
    connection: sqlite3.Connection | None = None
    try:
        if read_only:
            candidate, descriptor = open_verified_regular_file_for_read(
                db_path,
                require_owner_only_mode=True,
            )
            access_mode = "ro"
        else:
            _tighten_owner_only_directory(db_path.parent)
            candidate, descriptor = open_owner_only_file(
                db_path,
                flags=os.O_RDWR | os.O_CREAT,
                mode=0o600,
            )
            access_mode = "rw"
        descriptor_path = _sqlite_descriptor_path(descriptor)
        connection = sqlite3.connect(
            f"file:{descriptor_path}?mode={access_mode}",
            uri=True,
            check_same_thread=False,
        )
        result = connection
        connection = None
        return candidate, result
    except (StealthLogError, ArtifactBoundaryError):
        raise StealthLogError(_STEALTH_LOG_FAILURE) from None
    except Exception:
        raise StealthLogError(_STEALTH_LOG_FAILURE) from None
    finally:
        _safe_close_connection(connection)
        _safe_close_descriptor(descriptor)


def _generate_session_key() -> bytearray:
    """Generate a Fernet key or fail closed when encryption is unavailable."""
    if not _HAS_CRYPTO or Fernet is None:
        raise StealthLogError(_STEALTH_LOG_FAILURE)
    return bytearray(Fernet.generate_key())


def _validate_key(key: bytes | bytearray) -> None:
    if not _HAS_CRYPTO or Fernet is None:
        raise StealthLogError(_STEALTH_LOG_FAILURE)
    try:
        Fernet(bytes(key))
    except Exception:
        raise StealthLogError(_STEALTH_LOG_FAILURE) from None


def _encrypt(data: str, key: bytes | bytearray) -> str:
    _validate_key(key)
    assert Fernet is not None
    return Fernet(bytes(key)).encrypt(data.encode("utf-8")).decode("ascii")


def _decrypt(encrypted: str, key: bytes | bytearray) -> str:
    _validate_key(key)
    assert Fernet is not None
    return Fernet(bytes(key)).decrypt(encrypted.encode("ascii")).decode("utf-8")


def _tighten_owner_only_directory(directory: Path) -> None:
    """Create/validate one directory and force its leaf descriptor to ``0700``."""
    descriptor = -1
    try:
        descriptor = open_private_directory(directory, create=True)
        os.fchmod(descriptor, 0o700)
    except Exception:
        raise StealthLogError(_STEALTH_LOG_FAILURE) from None
    finally:
        _safe_close_descriptor(descriptor)


def _redacted_record(record: logging.LogRecord) -> dict[str, Any]:
    """Build and redact the complete persisted record, including all extras."""
    extras = {
        key: value
        for key, value in record.__dict__.items()
        if key not in _STANDARD_RECORD_FIELDS and key not in {"message", "asctime"}
    }
    try:
        message = record.getMessage()
    except Exception:
        message = str(record.msg)
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "level": record.levelname,
        "name": record.name,
        "message": message,
        "extra": extras,
    }
    protected = redact_value(entry)
    if not isinstance(protected, dict):
        return {"message": "<redacted>"}
    return protected


def _redacted_fallback_record(ts: Any, level: Any, message: str) -> dict[str, Any]:
    """Protect SQLite metadata even when a legacy payload cannot be trusted."""
    protected = redact_value(
        {"ts": str(ts), "level": str(level), "message": str(message)}
    )
    if isinstance(protected, dict):
        return protected
    return {"message": "<redacted>"}


class StealthLogHandler(logging.Handler):
    """Persist centrally redacted log records in owner-only encrypted SQLite."""

    def __init__(self, db_path: Path, session_key: bytearray) -> None:
        super().__init__()
        if not isinstance(session_key, bytearray):
            super().close()
            raise StealthLogError(_STEALTH_LOG_FAILURE)
        self._db_path = absolute_lexical_path(db_path)
        self._key = bytearray(session_key)
        self._conn: sqlite3.Connection | None = None
        self._record_count = 0
        self._closed = False
        self.addFilter(redaction_filter())
        try:
            _validate_key(self._key)
            _, self._conn = _connect_owner_only_database(
                self._db_path,
                read_only=False,
            )
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS stealth_log (
                    id       INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts       TEXT    NOT NULL,
                    level    TEXT    NOT NULL,
                    payload  TEXT    NOT NULL
                )
                """
            )
            self._conn.commit()
        except Exception:
            _safe_close_connection(self._conn)
            self._conn = None
            _wipe_bytearray(self._key)
            if isinstance(session_key, bytearray):
                _wipe_bytearray(session_key)
            super().close()
            raise StealthLogError(_STEALTH_LOG_FAILURE) from None

    def emit(self, record: logging.LogRecord) -> None:
        """Redact, encrypt, and store a complete log record."""
        self.acquire()
        try:
            connection = self._conn
            if self._closed or connection is None:
                return
            try:
                entry = _redacted_record(record)
                plaintext = redacted_json_dumps(
                    entry,
                    default=str,
                    separators=(",", ":"),
                )
                encrypted = _encrypt(plaintext, self._key)
                connection.execute(
                    "INSERT INTO stealth_log (ts, level, payload) VALUES (?, ?, ?)",
                    (
                        str(entry.get("ts", "")),
                        str(entry.get("level", "")),
                        encrypted,
                    ),
                )
                self._record_count += 1
                if self._record_count % 50 == 0:
                    connection.commit()
            except Exception:
                # Ordinary logging must not replace the scan's primary outcome.
                return
        finally:
            self.release()

    def flush(self) -> None:
        self.acquire()
        try:
            connection = getattr(self, "_conn", None)
            if connection is None:
                return
            try:
                connection.commit()
            except Exception:
                pass
        finally:
            self.release()

    def close(self) -> None:
        self.acquire()
        try:
            if getattr(self, "_closed", False):
                return
            self._closed = True
            connection = getattr(self, "_conn", None)
            try:
                if connection is not None:
                    try:
                        connection.commit()
                    finally:
                        connection.close()
            except Exception:
                pass
            finally:
                self._conn = None
                key = getattr(self, "_key", None)
                if isinstance(key, bytearray):
                    _wipe_bytearray(key)
                super().close()
        finally:
            self.release()


@dataclass(frozen=True)
class _RemovedConsoleHandler:
    logger: logging.Logger
    handler: logging.Handler
    index: int


@dataclass
class _StealthSession:
    db_path: Path
    handler: StealthLogHandler
    caller_key: bytearray
    root: logging.Logger
    removed_handlers: list[_RemovedConsoleHandler]
    propagation: list[tuple[logging.Logger, bool]]


_SESSION_LOCK = threading.RLock()
_ACTIVE_SESSIONS: dict[str, _StealthSession] = {}


def _session_identity(db_path: Path) -> str:
    return str(absolute_lexical_path(db_path))


def _managed_loggers() -> list[logging.Logger]:
    root = logging.getLogger()
    managed = [root]
    for name, candidate in logging.Logger.manager.loggerDict.items():
        if not isinstance(candidate, logging.Logger):
            continue
        if name == "forge" or name.startswith("forge.") or name == "netforge" or name.startswith("netforge."):
            managed.append(candidate)
    # Logger dictionaries can expose the same object under aliases in tests.
    return list(dict.fromkeys(managed))


def _is_console_handler(handler: logging.Handler) -> bool:
    return type(handler) is logging.StreamHandler or type(handler).__name__ == "RichHandler"


def _restore_session_logging(session: _StealthSession) -> None:
    try:
        session.root.removeHandler(session.handler)
    except Exception:
        pass
    for logger, prior in session.propagation:
        try:
            logger.propagate = prior
        except Exception:
            pass
    grouped: dict[logging.Logger, list[_RemovedConsoleHandler]] = {}
    for removed in session.removed_handlers:
        grouped.setdefault(removed.logger, []).append(removed)
    for logger, records in grouped.items():
        for removed in sorted(records, key=lambda item: item.index):
            try:
                if removed.handler not in logger.handlers:
                    logger.handlers.insert(
                        min(removed.index, len(logger.handlers)),
                        removed.handler,
                    )
            except Exception:
                pass


def _finalize_session(session: _StealthSession) -> None:
    """Restore logging, drain the writer, and destroy both owned key copies."""
    try:
        _restore_session_logging(session)
        session.handler.acquire()
        try:
            session.handler.flush()
            session.handler.close()
        finally:
            session.handler.release()
    except Exception:
        # Finalization is a cleanup boundary and must not mask scan outcomes.
        try:
            session.handler.close()
        except Exception:
            pass
    finally:
        _wipe_bytearray(session.caller_key)


def _finalize_all_sessions_locked() -> None:
    """Finalize every registered session while the global transaction is held."""
    sessions = list(_ACTIVE_SESSIONS.values())
    _ACTIVE_SESSIONS.clear()
    for session in sessions:
        _finalize_session(session)


def finalize_stealth_logging(db_path: Path) -> bool:
    """Detach and close the matching active handler; safe to call repeatedly."""
    identity = _session_identity(db_path)
    with _SESSION_LOCK:
        session = _ACTIVE_SESSIONS.pop(identity, None)
        if session is None:
            return False
        _finalize_session(session)
        return True


def install_stealth_logging(
    results_dir: Path,
    session_key: bytearray | None = None,
) -> bytearray:
    """Install the single global handler and return its mutable caller key."""
    db_path = absolute_lexical_path(results_dir) / "stealth.db"
    if session_key is not None and not isinstance(session_key, bytearray):
        raise StealthLogError(_STEALTH_LOG_FAILURE)

    with _SESSION_LOCK:
        identity = _session_identity(db_path)
        active = _ACTIVE_SESSIONS.get(identity)
        if active is not None:
            if session_key is not None and session_key is not active.caller_key:
                _wipe_bytearray(session_key)
                raise StealthLogError(_STEALTH_LOG_FAILURE)
            return active.caller_key

        # Root logging is process-global.  A different-path install supersedes
        # the prior session atomically rather than stacking handlers/snapshots.
        _finalize_all_sessions_locked()

        key_material = session_key if session_key is not None else _generate_session_key()
        handler: StealthLogHandler | None = None
        session: _StealthSession | None = None
        removed: list[_RemovedConsoleHandler] = []
        propagation: list[tuple[logging.Logger, bool]] = []
        root = logging.getLogger()
        try:
            handler = StealthLogHandler(db_path, key_material)
            handler.setLevel(logging.DEBUG)
            for logger in _managed_loggers():
                if logger is not root:
                    propagation.append((logger, logger.propagate))
                    logger.propagate = True
                for index, existing in list(enumerate(logger.handlers)):
                    if _is_console_handler(existing):
                        logger.removeHandler(existing)
                        removed.append(_RemovedConsoleHandler(logger, existing, index))
            root.addHandler(handler)
            session = _StealthSession(
                db_path=db_path,
                handler=handler,
                caller_key=key_material,
                root=root,
                removed_handlers=removed,
                propagation=propagation,
            )
            _ACTIVE_SESSIONS[_session_identity(db_path)] = session
            log.debug("Private session logging installed")
            return key_material
        except BaseException as exc:
            if session is not None:
                if _ACTIVE_SESSIONS.get(identity) is session:
                    _ACTIVE_SESSIONS.pop(identity, None)
                _finalize_session(session)
            else:
                if handler is not None:
                    provisional = _StealthSession(
                        db_path=db_path,
                        handler=handler,
                        caller_key=key_material,
                        root=root,
                        removed_handlers=removed,
                        propagation=propagation,
                    )
                    _finalize_session(provisional)
                else:
                    _wipe_bytearray(key_material)
            if isinstance(exc, Exception):
                raise StealthLogError(_STEALTH_LOG_FAILURE) from None
            raise


def dump_stealth_log(
    db_path: Path,
    session_key: bytearray,
    output_path: Path | None = None,
    level_filter: str | None = None,
) -> list[dict[str, Any]]:
    """Consume the caller key, finalize the writer, and redact every output."""
    local_key = bytearray()
    connection: sqlite3.Connection | None = None
    rows: list[tuple[Any, ...]] = []
    records: list[dict[str, Any]] = []
    try:
        if not isinstance(session_key, bytearray):
            raise StealthLogError(_STEALTH_LOG_FAILURE)
        with _SESSION_LOCK:
            try:
                local_key.extend(session_key)
                candidate = absolute_lexical_path(db_path)
                identity = _session_identity(candidate)
                active = _ACTIVE_SESSIONS.pop(identity, None)
                if active is not None:
                    _finalize_session(active)

                _validate_key(local_key)
                _, connection = _connect_owner_only_database(candidate, read_only=True)
                if level_filter:
                    rows = connection.execute(
                        "SELECT ts, level, payload FROM stealth_log WHERE level = ? ORDER BY id",
                        (str(level_filter).upper(),),
                    ).fetchall()
                else:
                    rows = connection.execute(
                        "SELECT ts, level, payload FROM stealth_log ORDER BY id"
                    ).fetchall()

                for ts, level, encrypted_payload in rows:
                    decrypted = ""
                    parsed: Any = None
                    try:
                        decrypted = _decrypt(str(encrypted_payload), local_key)
                        parsed = json.loads(decrypted)
                        protected = redact_value(parsed)
                        if isinstance(protected, dict):
                            records.append(protected)
                        else:
                            records.append(
                                _redacted_fallback_record(ts, level, "<redacted>")
                            )
                    except Exception:
                        records.append(
                            _redacted_fallback_record(
                                ts,
                                level,
                                "[DECRYPTION FAILED]",
                            )
                        )
                    finally:
                        decrypted = ""
                        parsed = None

                if output_path is not None:
                    payload = redacted_json_dumps(
                        records,
                        indent=2,
                        default=str,
                    ).encode("utf-8")
                    atomic_write_bytes(output_path, payload, mode=0o600)
                return records
            finally:
                _safe_close_connection(connection)
                connection = None
                rows.clear()
                _wipe_bytearray(local_key)
                _wipe_bytearray(session_key)
    except (StealthLogError, ArtifactBoundaryError):
        raise StealthLogError(_STEALTH_LOG_FAILURE) from None
    except Exception:
        raise StealthLogError(_STEALTH_LOG_FAILURE) from None
    finally:
        _safe_close_connection(connection)
        rows.clear()
        _wipe_bytearray(local_key)
        if isinstance(session_key, bytearray):
            _wipe_bytearray(session_key)
