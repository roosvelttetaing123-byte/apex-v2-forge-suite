"""Enrichment Cache — cache Shodan/crt.sh/DNS results to avoid re-querying.

SQLite-backed cache with TTL support for OSINT API responses.
Prevents hammering rate-limited APIs during iterative scans.

FOR AUTHORIZED PENETRATION TESTING AND RED TEAM OPERATIONS ONLY.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import time
import weakref
from pathlib import Path
from typing import Any

from sqlalchemy import Column, Float, Integer, String, Text, create_engine
from sqlalchemy.engine import URL
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from common import db as database_boundary
from common.redaction import REDACTED, redact_secret_fragments, redact_value

log = logging.getLogger("forge.leak_intel.enrichment_cache")


class EnrichmentCacheInitializationError(RuntimeError):
    """Fixed public failure for enrichment-cache schema initialization."""


class _EnrichmentCacheArtifactError(ValueError):
    """Fixed public failure for an unsafe enrichment-cache artifact."""


def _sensitive_literals(value: Any, *, key: str = "response") -> set[str]:
    markers = (
        "secret", "password", "token", "credential", "match", "detail",
        "response", "payload", "body", "content", "value", "raw",
        "private_key", "access_key",
    )
    found: set[str] = set()
    if isinstance(value, dict):
        for child_key, child in value.items():
            found.update(_sensitive_literals(child, key=str(child_key)))
    elif isinstance(value, (list, tuple, set)):
        for child in value:
            found.update(_sensitive_literals(child, key=key))
    elif isinstance(value, str) and value and any(
        marker in key.lower() for marker in markers
    ):
        found.add(value)
    return found


def _replace_literals(value: Any, literals: set[str]) -> Any:
    if isinstance(value, str):
        return redact_secret_fragments(value, literals)
    if isinstance(value, dict):
        return {
            _replace_literals(key, literals): _replace_literals(child, literals)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_replace_literals(child, literals) for child in value]
    return value


def _looks_opaque_secret(value: str) -> bool:
    """Return whether one cache input has token-like secret characteristics."""
    return (
        len(value) >= 20
        and not any(character.isspace() for character in value)
        and bool(re.fullmatch(r"[A-Za-z0-9._~+/=-]+", value))
        and any(character.isalpha() for character in value)
        and any(character.isdigit() for character in value)
    )


def _safe_response(value: Any, *, transient_secrets: set[str] | None = None) -> Any:
    """Return a detached response with exact risky-field values removed."""
    literals = _sensitive_literals(value)
    literals.update(transient_secrets or set())
    detached = _replace_literals(redact_value(value), literals)

    def suppress_opaque(item: Any) -> Any:
        if isinstance(item, str):
            if item == REDACTED:
                return item
            # Unknown provider response fields are an ordinary persistence
            # boundary. Retain public host/URL context, but suppress long
            # token-like strings that have no sensitive field label.
            public_context = bool(
                re.fullmatch(
                    r"(?:https?://[^\s]+|(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}|"
                    r"(?:\d{1,3}\.){3}\d{1,3})",
                    item,
                )
            )
            opaque = _looks_opaque_secret(item)
            return REDACTED if opaque and not public_context else item
        if isinstance(item, dict):
            return {
                suppress_opaque(key): suppress_opaque(child)
                for key, child in item.items()
            }
        if isinstance(item, list):
            return [suppress_opaque(child) for child in item]
        return item

    return suppress_opaque(detached)


def _safe_source(value: str) -> str:
    normalized = value.strip().lower()
    if normalized in _DEFAULT_TTLS and normalized != "default":
        return normalized
    digest = hashlib.sha256(normalized.encode("utf-8", "replace")).hexdigest()
    return f"sha256:{digest}"

# Default TTLs in seconds
_DEFAULT_TTLS: dict[str, int] = {
    "crtsh":          86400,    # 24 hours — CT logs don't change fast
    "shodan":         43200,    # 12 hours — services change moderately
    "dns_history":    86400,    # 24 hours — historical data is static
    "passivetotal":   86400,    # 24 hours
    "securitytrails": 86400,    # 24 hours
    "default":        21600,    # 6 hours fallback
}


class CacheBase(DeclarativeBase):
    """Declarative base for cache ORM."""


class CacheEntry(CacheBase):
    """A cached OSINT API response."""
    __tablename__ = "enrichment_cache"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    cache_key  = Column(String(500), nullable=False, unique=True, index=True)
    source     = Column(String(100), nullable=False)   # crtsh, shodan, dns_history, etc.
    query      = Column(String(500), nullable=False)   # The original query
    response   = Column(Text, nullable=False)           # JSON-encoded response
    created_at = Column(Float, nullable=False)
    ttl        = Column(Integer, nullable=False)        # TTL in seconds


class EnrichmentCache:
    """Cache for OSINT API responses with automatic TTL expiration.

    Usage::
        cache = EnrichmentCache(db_path=Path("leak_intel.db"))
        # Try cache first
        data = cache.get("crtsh", "example.com")
        if data is None:
            data = await query_crtsh("example.com")
            cache.set("crtsh", "example.com", data)
    """

    def __init__(self, db_path: Path | None = None) -> None:
        if db_path is None:
            db_path = Path("enrichment_cache.db")
        db_path = database_boundary._absolute_artifact_path(Path(db_path))
        engine: Any | None = None
        try:
            engine = create_engine(
                URL.create("sqlite+pysqlite", database=os.fspath(db_path)),
                creator=lambda: database_boundary._connect_sqlite_file(db_path),
                echo=False,
            )
            with database_boundary._db_schema_lock(db_path):
                CacheBase.metadata.create_all(engine)
            self._db_path = db_path
            self._secure_paths()
            self._engine = engine
            self._session_factory = sessionmaker(bind=engine)
            self._engine_finalizer = weakref.finalize(
                self,
                database_boundary._safe_dispose_engine,
                engine,
            )
        except _EnrichmentCacheArtifactError:
            if engine is not None:
                database_boundary._safe_dispose_engine(engine)
            raise
        except database_boundary._DatabaseArtifactError:
            if engine is not None:
                database_boundary._safe_dispose_engine(engine)
            raise _EnrichmentCacheArtifactError(
                "enrichment cache artifact is unavailable or unsafe"
            ) from None
        except Exception:
            if engine is not None:
                database_boundary._safe_dispose_engine(engine)
            raise EnrichmentCacheInitializationError(
                "enrichment cache initialization failed"
            ) from None

    def close(self) -> None:
        """Release the cache's private SQLite pool deterministically."""

        database_boundary._safe_dispose_engine(self._engine)
        if self._engine_finalizer.alive:
            self._engine_finalizer.detach()

    def _secure_paths(self) -> None:
        descriptor = -1
        try:
            descriptor = database_boundary._open_owner_only_regular_file(
                self._db_path,
                create=False,
            )
            database_boundary._safe_close_descriptor(descriptor)
            descriptor = -1
            database_boundary._secure_existing_sqlite_sidecars(self._db_path)
        except Exception:
            raise _EnrichmentCacheArtifactError(
                "enrichment cache artifact is unavailable or unsafe"
            ) from None
        finally:
            database_boundary._safe_close_descriptor(descriptor)

    def _make_key(self, source: str, query: str) -> str:
        """Build a non-disclosing, deterministic cache key."""
        material = f"{source.strip().lower()}\x00{query.strip().lower()}"
        digest = hashlib.sha256(material.encode("utf-8", "replace")).hexdigest()
        return f"sha256:{digest}"

    def get(self, source: str, query: str) -> Any | None:
        """Retrieve a cached response if it exists and hasn't expired.

        Args:
            source: API source name (crtsh, shodan, etc.).
            query:  The original query string.

        Returns:
            Parsed JSON data, or None if cache miss or expired.
        """
        key = self._make_key(source, query)
        self._secure_paths()
        session = self._session_factory()
        try:
            entry = session.query(CacheEntry).filter_by(cache_key=key).first()
            if entry is None:
                return None

            # Check TTL
            age = time.time() - entry.created_at
            if age > entry.ttl:
                # Expired — remove it
                session.delete(entry)
                session.commit()
                log.debug("Cache expired: %s (age=%.0fs, ttl=%ds)", key, age, entry.ttl)
                return None

            log.debug("Cache hit: %s (age=%.0fs)", key, age)
            return json.loads(entry.response)  # type: ignore[arg-type]
        except Exception as exc:
            log.debug("Cache read error (%s)", type(exc).__name__)
            return None
        finally:
            session.close()
            self._secure_paths()

    def set(self, source: str, query: str, data: Any, ttl: int | None = None) -> None:
        """Store a response in the cache.

        Args:
            source: API source name.
            query:  The original query string.
            data:   Response data (must be JSON-serializable).
            ttl:    Cache TTL in seconds. Uses source default if not specified.
        """
        key = self._make_key(source, query)
        if ttl is None:
            ttl = _DEFAULT_TTLS.get(source, _DEFAULT_TTLS["default"])

        safe_source = _safe_source(source)
        safe_query = key
        transient_secrets = {
            value
            for value in (str(source), str(query))
            if _looks_opaque_secret(value)
        }
        safe_data = _safe_response(data, transient_secrets=transient_secrets)
        # ``redact_value`` returns detached containers.  Serialize only that
        # detached form so a provider response cannot write raw values first
        # and be sanitized later.
        safe_response = json.dumps(safe_data, ensure_ascii=True)

        self._secure_paths()
        session = self._session_factory()
        try:
            # Upsert
            existing = session.query(CacheEntry).filter_by(cache_key=key).first()
            if existing:
                existing.source = safe_source  # type: ignore[assignment]
                existing.query = safe_query  # type: ignore[assignment]
                existing.response = safe_response  # type: ignore[assignment]
                existing.created_at = time.time()  # type: ignore[assignment]
                existing.ttl = ttl  # type: ignore[assignment]
            else:
                entry = CacheEntry(
                    cache_key=key,
                    source=safe_source,
                    query=safe_query,
                    response=safe_response,
                    created_at=time.time(),
                    ttl=ttl,
                )
                session.add(entry)
            session.commit()
            log.debug("Cache set: %s (ttl=%ds)", key, ttl)
        except Exception as exc:
            log.debug("Cache write error (%s)", type(exc).__name__)
            session.rollback()
        finally:
            session.close()
            self._secure_paths()

    def invalidate(self, source: str, query: str) -> None:
        """Remove a specific cache entry."""
        key = self._make_key(source, query)
        self._secure_paths()
        session = self._session_factory()
        try:
            entry = session.query(CacheEntry).filter_by(cache_key=key).first()
            if entry:
                session.delete(entry)
                session.commit()
        except Exception as exc:
            log.debug("Cache invalidate error (%s)", type(exc).__name__)
        finally:
            session.close()
            self._secure_paths()

    def flush(self, source: str | None = None) -> int:
        """Flush cache entries. If source specified, only flush that source.

        Returns:
            Number of entries removed.
        """
        self._secure_paths()
        session = self._session_factory()
        try:
            if source:
                count = session.query(CacheEntry).filter_by(source=_safe_source(source)).delete()
            else:
                count = session.query(CacheEntry).delete()
            session.commit()
            return count
        except Exception as exc:
            log.debug("Cache flush error (%s)", type(exc).__name__)
            session.rollback()
            return 0
        finally:
            session.close()
            self._secure_paths()

    def stats(self) -> dict[str, Any]:
        """Return cache statistics."""
        self._secure_paths()
        session = self._session_factory()
        try:
            total = session.query(CacheEntry).count()
            now = time.time()
            expired = sum(
                1 for e in session.query(CacheEntry).all()
                if (now - e.created_at) > e.ttl
            )
            by_source: dict[str, int] = {}
            for entry in session.query(CacheEntry).all():
                source = str(entry.source)
                by_source[source] = by_source.get(source, 0) + 1
            return {
                "total_entries": total,
                "expired_entries": expired,
                "active_entries": total - expired,
                "by_source": by_source,
            }
        except Exception:
            return {"total_entries": 0}
        finally:
            session.close()
            self._secure_paths()


class TestEnrichmentCache:
    """Unit tests for enrichment_cache."""

    def test_set_and_get(self, tmp_path: Path) -> None:
        cache = EnrichmentCache(tmp_path / "test_cache.db")
        cache.set("crtsh", "example.com", {"subdomains": ["a.example.com"]})
        result = cache.get("crtsh", "example.com")
        assert result is not None
        assert result["subdomains"] == ["a.example.com"]

    def test_cache_miss(self, tmp_path: Path) -> None:
        cache = EnrichmentCache(tmp_path / "test_cache.db")
        result = cache.get("crtsh", "nonexistent.com")
        assert result is None

    def test_ttl_expiration(self, tmp_path: Path) -> None:
        cache = EnrichmentCache(tmp_path / "test_cache.db")
        cache.set("crtsh", "example.com", {"data": True}, ttl=0)
        # TTL=0 means already expired
        import time
        time.sleep(0.1)
        result = cache.get("crtsh", "example.com")
        assert result is None

    def test_flush(self, tmp_path: Path) -> None:
        cache = EnrichmentCache(tmp_path / "test_cache.db")
        cache.set("crtsh", "a.com", {"x": 1})
        cache.set("shodan", "b.com", {"y": 2})
        count = cache.flush("crtsh")
        assert count == 1
        assert cache.get("shodan", "b.com") is not None

    def test_stats(self, tmp_path: Path) -> None:
        cache = EnrichmentCache(tmp_path / "test_cache.db")
        cache.set("crtsh", "a.com", {"x": 1})
        cache.set("shodan", "b.com", {"y": 2})
        s = cache.stats()
        assert s["total_entries"] == 2
